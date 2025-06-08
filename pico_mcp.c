#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "llhttp.h"
#include "parson.h"

enum endpoint_type {
	ENDPOINT_NONE,
	ENDPOINT_SSE,
	ENDPOINT_MESSAGE,
	ENDPOINT_EVENT,
	ENDPOINT_NOT_FOUND
};

typedef struct session_info {
	llhttp_t parser;
	llhttp_settings_t settings;
	struct tcp_pcb *pcb;
	char *url;
	char *query;
	enum endpoint_type endpoint_type;
	char *request;
	char *response;
} session_info_t;

static struct tcp_pcb *sse_pcb = NULL;
static const char empty_string[] = "";
static int response_id = 1;
static bool led_on = false;

static int on_url(llhttp_t *parser, const char *at, size_t length);
static int on_url_complete(llhttp_t *parser);
static int on_body(llhttp_t *parser, const char *at, size_t length);
static int on_message_complete(llhttp_t *parser);

static void switch_led(const char *val)
{
	led_on = (strcmp(val, "ON") == 0) ? true : false;
	cyw43_gpio_set(&cyw43_state, 0, led_on);
}

void session_info_free(session_info_t *info)
{
	free(info->url);
	free(info->request);
	free(info->response);
	free(info);
}

const char response_200[] =
	"HTTP/1.1 200 OK\r\n"
	"Content-Type: text/event-stream\r\n"
	"Cache-Control: no-cache\r\n"
	"Connection: keep-alive\r\n\r\n";
const char response_404[] = "HTTP/1.1 404 Not Found\r\n\r\n";
const char response_202[] =
	"HTTP/1.1 202 Accepted\r\n"
	"Transfer-Encoding: chunked\r\n"
	"\r\n"
	"8\r\n"
	"Accepted\r\n"
	"0\r\n"
	"\r\n";

static err_t http_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *pbuf, err_t err)
{
	session_info_t *info = (session_info_t *)arg;
	llhttp_t *parser = &info->parser;
	if (pbuf == NULL) {
		session_info_free(info);
		tcp_arg(tpcb, NULL);
		tcp_close(tpcb);
		return ERR_OK;
	}

	// HTTPリクエストのパース
	for (struct pbuf *p = pbuf; p != NULL; p = p->next) {
		llhttp_execute(parser, p->payload, p->len);
	}
	pbuf_free(pbuf);

	// レスポンスの送信
	if (info->response != NULL) {
		if (sse_pcb != NULL)
			tcp_write(sse_pcb, info->response, strlen(info->response), TCP_WRITE_FLAG_COPY);
		free(info->response);
		info->response = NULL;
	}

	return ERR_OK;
}

static err_t http_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	session_info_t *info = malloc(sizeof(session_info_t));
	if (info == NULL)
		return ERR_MEM;

	info->pcb = newpcb;
	info->url = NULL;
	info->query = NULL;
	info->endpoint_type = ENDPOINT_NONE;
	info->response = NULL;
	info->request = NULL;

	llhttp_t *parser = &info->parser;
	llhttp_settings_t *settings = (llhttp_settings_t *)&info->settings;
	llhttp_settings_init(settings);
	settings->on_url = on_url;
	settings->on_url_complete = on_url_complete;
	settings->on_body = on_body;
	settings->on_message_complete = on_message_complete;

	llhttp_init(parser, HTTP_REQUEST, settings);

	tcp_arg(newpcb, parser);
	tcp_recv(newpcb, http_recv_cb);

	return ERR_OK;
}

void http_server_init(void)
{
	struct tcp_pcb *pcb = tcp_new();
	tcp_bind(pcb, IP_ADDR_ANY, 80);
	pcb = tcp_listen(pcb);
	tcp_accept(pcb, http_accept_cb);
}

int response_printf(session_info_t *info, const char *format, ...)
{
	char header[64];
	const char footer[] = "\r\n";
	va_list args;
	va_start(args, format);
	int len = vsnprintf(NULL, 0, format, args);
	va_end(args);

	if (len < 0) {
		return -1; // エラー
	}

	int header_len = snprintf(header, sizeof(header), "\r\n\r\n%x\r\nevent: message\r\ndata: ", (int)(22 + len + sizeof(footer)));

	info->response = malloc(header_len + len + sizeof(footer) + 1);
	if (!info->response) {
		return -1; // メモリ不足
	}

	strcpy(info->response, header);
	va_start(args, format);
	vsnprintf(&info->response[header_len - 1], len + 1, format, args);
	va_end(args);
	strcat(&info->response[header_len + len - 1], footer);

	return len;
}

const char invalid_request[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}";
const char method_not_found[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}";
const char location_not_configured[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32001, \"message\": \"Location not configured\"}, \"id\": %d}\n";
const char unknown_tool[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32602,\"message\":\"Unknown tool\"}}";
const char invalid_protocol[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32602,\"message\":\"Invalid protocol version\"}}";
const char invalid_context[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Invalid context\"}, \"id\": %d}\n";
const char missing_fields[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing fields\"}, \"id\": %d}\n";
const char missing_call_arguments[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing call arguments\"}, \"id\": %d}\n";
const char parse_error[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}";

const char resource[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"logging\":{},\"tools\":{\"listChanged\":true}},\"serverInfo\":{\"name\":\"Raspberry Pi Pico Smart Home\",\"description\":\"A smart home system based on Raspberry Pi Pico.\",\"version\":\"1.0.0.0\"}}}";
const char tool_list[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":[{\"name\":\"switch.set\",\"description\":\"Turn the switch ON or OFF.\",\"inputSchema\":{\"title\":\"switch.set\",\"description\":\"Turn the switch ON or OFF.\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"state\":{\"type\":\"string\",\"enum\":[\"on\",\"off\"]}},\"required\":[\"switch_id\",\"state\"]}},{\"name\":\"switch.set_location\",\"description\":\"Set the location of the switch.\",\"inputSchema\":{\"title\":\"switch.set_location\",\"description\":\"Set the location of the switch.\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"}},\"required\":[\"switch_id\",\"location\"]}}]}}";
const char status_ok[] = "{\"jsonrpc\": \"2.0\", \"result\": {\"status\": \"ok\"}, \"id\": %d}\n";
const char call_success[] = "{\"jsonrpc\": \"2.0\", \"result\": {\"success\": true, \"url\": \"%s\", \"switch_id\": \"%s\", \"state\": \"%s\"}, \"id\": %d}\n";

// コンテキスト保持（簡易構造体）
typedef struct
{
	char location[32];
	char url[128];
} SwitchServerContext;

SwitchServerContext context;

void handle_set_context(session_info_t *info, JSON_Object *params, int id)
{
	JSON_Object *ctx = json_object_get_object(params, "context");
	if (!ctx) {
		response_printf(info, invalid_context, id);
		return;
	}

	JSON_Object *server = json_object_dotget_object(ctx, "switch_servers.servers[0]");
	const char *loc = json_object_get_string(server, "location");
	const char *url = json_object_get_string(server, "url");

	if (loc && url) {
		strncpy(context.location, loc, sizeof(context.location));
		strncpy(context.url, url, sizeof(context.url));

		response_printf(info, status_ok, id);
	}
	else {
		response_printf(info, missing_fields, id);
	}
}

void handle_call(session_info_t *info, JSON_Object *params, int id)
{
	const char *loc = json_object_get_string(params, "location");
	const char *switch_id = json_object_get_string(params, "switch_id");
	const char *state = json_object_get_string(params, "state");

	if (!loc || !switch_id || !state) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	if (strcmp(loc, context.location) == 0) {
		switch_led(state);
		response_printf(info, call_success, context.url, switch_id, state, id);
	}
	else {
		response_printf(info, location_not_configured, id);
	}
}

static int on_url(llhttp_t *parser, const char *at, size_t length)
{
	session_info_t *info = (session_info_t *)parser;
	size_t len;
	if (info->url) {
		len = strlen(info->url) + length + 1;
		char *new_requests = realloc((void *)info->url, len);
		if (!new_requests) {
			return -1; // メモリ不足
		}
		info->url = new_requests;
		strncat((char *)info->url, at, length);
	}
	else {
		len = length + 1;
		info->url = malloc(len);
		if (!info->url) {
			return -1; // メモリ不足
		}
		strncpy((char *)info->url, at, length);
	}

	info->url[len - 1] = '\0'; // Null-terminate

	return 0;
}

static int on_url_complete(llhttp_t *parser)
{
	session_info_t *info = (session_info_t *)parser;

	for (char *pos = info->url; *pos != '\0'; pos++) {
		if (*pos == '?') {
			*pos = '\0';
			info->query = &pos[1];
			break;
		}
	}

	if (strcmp(info->url, "/sse") == 0) {
		info->endpoint_type = ENDPOINT_SSE;
	}
	else if (strcmp(info->url, "/message") == 0) {
		info->endpoint_type = ENDPOINT_MESSAGE;
	}
	else if (strcmp(info->url, "/event") == 0) {
		info->endpoint_type = ENDPOINT_EVENT;
	}
	else {
		info->endpoint_type = ENDPOINT_NOT_FOUND;
	}
	return 0; // 成功
}

static int on_body(llhttp_t *parser, const char *at, size_t length)
{
	session_info_t *info = (session_info_t *)parser;
	size_t len;
	if (info->request) {
		len = strlen(info->request) + length + 1;
		char *new_requests = realloc((void *)info->request, len);
		if (!new_requests) {
			return -1; // メモリ不足
		}
		info->request = new_requests;
		strncat((char *)info->request, at, length);
	}
	else {
		len = length + 1;
		info->request = malloc(len);
		if (!info->request) {
			return -1; // メモリ不足
		}
		strncpy((char *)info->request, at, length);
	}

	info->request[len - 1] = '\0'; // Null-terminate

	return 0;
}

static int on_message_complete(llhttp_t *parser)
{
	session_info_t *info = (session_info_t *)parser;

	switch (info->endpoint_type) {
	case ENDPOINT_SSE:
		sse_pcb = info->pcb; // SSE用のPCBを保存
		tcp_write(info->pcb, response_200, strlen(response_200), TCP_WRITE_FLAG_COPY);
		break;
	case ENDPOINT_MESSAGE:
	case ENDPOINT_EVENT:
		tcp_write(info->pcb, response_202, strlen(response_202), TCP_WRITE_FLAG_COPY);
		break;
	case ENDPOINT_NOT_FOUND: 
		tcp_write(info->pcb, response_404, strlen(response_404), TCP_WRITE_FLAG_COPY);
		break;
	}

	JSON_Value *val = json_parse_string(info->request);
	if (!val) {
		response_printf(info, parse_error, response_id);
		response_id++;
		return 0;
	}

	JSON_Object *obj = json_value_get_object(val);
	const char *method = json_object_get_string(obj, "method");
	int id = (int)json_object_get_number(obj, "id");
	JSON_Object *params = json_object_get_object(obj, "params");
	const char *name = json_object_get_string(params, "name");
	JSON_Object *arguments = json_object_get_object(obj, "arguments");

	if (strcmp(method, "initialize") == 0) {
		const char *version = json_object_get_string(params, "protocolVersion");
		if (version && strcmp(version, "2025-03-26") == 0) {
			response_printf(info, resource, id);
		}
		else {
			response_printf(info, invalid_protocol, id);
		}
	}
	else if (strcmp(method, "notifications/initialized") == 0) {

	}
	else if (strcmp(method, "tools/list") == 0) {
		response_printf(info, tool_list, id);
	}
	else if (strcmp(method, "tools/call") == 0 && name != NULL) {
		if (strcmp(name, "mcp.set_context") == 0) {
			handle_set_context(info, arguments, id);
		}
		else if (strcmp(name, "mcp.call") == 0) {
			handle_call(info, arguments, id);
		}
	}
	else {
		response_printf(info, method_not_found, id);
	}

	json_value_free(val);

	return 0;
}

int main()
{
	stdio_init_all();

	// Initialise the Wi-Fi chip
	if (cyw43_arch_init()) {
		printf("Wi-Fi init failed\n");
		return -1;
	}

	// Enable wifi station
	cyw43_arch_enable_sta_mode();

	printf("Connecting to Wi-Fi...\n");
	if (cyw43_arch_wifi_connect_timeout_ms("Your Wi-Fi SSID", "Your Wi-Fi Password", CYW43_AUTH_WPA2_AES_PSK, 30000)) {
		printf("failed to connect.\n");
		return 1;
	}
	else {
		printf("Connected.\n");
		// Read the ip address in a human readable way
		uint8_t *ip_address = (uint8_t *)&(cyw43_state.netif[0].ip_addr.addr);
		printf("IP address %d.%d.%d.%d\n", ip_address[0], ip_address[1], ip_address[2], ip_address[3]);
	}

	http_server_init();
	printf("HTTP server initialized.\n");

	while (true) {
		sleep_ms(1000);
	}
}
