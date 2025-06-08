#include <stdio.h>
#include <string.h>
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

enum endpoint_type endpoint_type = ENDPOINT_NONE;
static struct tcp_pcb *sse_pcb = NULL;
static llhttp_t parser;
static const char empty_string[] = "";
static char *response = NULL;
static int response_id = 1;
static bool led_on = false;

static void switch_led(const char *val)
{
	led_on = (strcmp(val, "ON") == 0) ? true : false;
	cyw43_gpio_set(&cyw43_state, 0, led_on);
}

static int on_url(llhttp_t *parser, const char *url, size_t length)
{
	if (strcmp(url, "/sse") == 0) {
		endpoint_type = ENDPOINT_SSE;
	}
	else if (strcmp(url, "/message") == 0 && sse_pcb) {
		endpoint_type = ENDPOINT_MESSAGE;
	}
	else if (strcmp(url, "/event") == 0 && sse_pcb) {
		endpoint_type = ENDPOINT_EVENT;
	}
	else {
		endpoint_type = ENDPOINT_NOT_FOUND;
	}
	return 0; // 成功
}

static int on_body(llhttp_t *parser, const char *at, size_t length);
static int on_message_complete(llhttp_t *parser);

static err_t http_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *pbuf, err_t err)
{
	if (!pbuf)
		return ERR_OK;

	// HTTPリクエストのパース
	for (struct pbuf *p = pbuf; p != NULL; p = p->next) {
		llhttp_execute(&parser, p->payload, p->len);
	}
	pbuf_free(pbuf);

	switch (endpoint_type) {
	case ENDPOINT_SSE:
		sse_pcb = tpcb; // SSE用のPCBを保存
		endpoint_type = ENDPOINT_NONE; // リセット
		break;
	case ENDPOINT_MESSAGE:
	case ENDPOINT_EVENT:
		endpoint_type = ENDPOINT_NONE; // リセット
		break;
	case ENDPOINT_NOT_FOUND: {
		const char *res404 = "HTTP/1.1 404 Not Found\r\n\r\n";
		tcp_write(tpcb, res404, strlen(res404), TCP_WRITE_FLAG_COPY);
		endpoint_type = ENDPOINT_NONE; // リセット
		break;
	}
	}

	// レスポンスの送信
	if (response != NULL) {
		tcp_write(tpcb, response, strlen(response), TCP_WRITE_FLAG_COPY);
		free(response);
		response = NULL;
	}

	return ERR_OK;
}

static err_t http_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
	llhttp_settings_t settings;
	llhttp_settings_init(&settings);
	settings.on_url = on_url;
	settings.on_body = on_body;
	settings.on_message_complete = on_message_complete;

	llhttp_init(&parser, HTTP_REQUEST, &settings);

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

int response_printf(const char *format, ...)
{
	va_list args;
	va_start(args, format);
	int len = vsnprintf(NULL, 0, format, args);
	va_end(args);

	if (len < 0) {
		return -1; // エラー
	}

	response = malloc(len + 1);
	if (!response) {
		return -1; // メモリ不足
	}

	va_start(args, format);
	vsnprintf(response, len + 1, format, args);
	va_end(args);

	return len;
}

// コンテキスト保持（簡易構造体）
typedef struct
{
	char location[32];
	char url[128];
} SwitchServerContext;

SwitchServerContext context;

void handle_set_context(JSON_Object *params, int id)
{
	JSON_Object *ctx = json_object_get_object(params, "context");
	if (!ctx) {
		printf("{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Invalid context\"}, \"id\": %d}\n", id);
		return;
	}

	JSON_Object *server = json_object_dotget_object(ctx, "switch_servers.servers[0]");
	const char *loc = json_object_get_string(server, "location");
	const char *url = json_object_get_string(server, "url");

	if (loc && url) {
		strncpy(context.location, loc, sizeof(context.location));
		strncpy(context.url, url, sizeof(context.url));

		printf("{\"jsonrpc\": \"2.0\", \"result\": {\"status\": \"ok\"}, \"id\": %d}\n", id);
	}
	else {
		printf("{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing fields\"}, \"id\": %d}\n", id);
	}
}

void handle_call(JSON_Object *params, int id)
{
	const char *loc = json_object_get_string(params, "location");
	const char *switch_id = json_object_get_string(params, "switch_id");
	const char *state = json_object_get_string(params, "state");

	if (!loc || !switch_id || !state) {
		printf("{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing call arguments\"}, \"id\": %d}\n", id);
		return;
	}

	if (strcmp(loc, context.location) == 0) {
		switch_led(state);
		printf("{\"jsonrpc\": \"2.0\", \"result\": {\"success\": true, \"url\": \"%s\", \"switch_id\": \"%s\", \"state\": \"%s\"}, \"id\": %d}\n",
			context.url, switch_id, state, id);
	}
	else {
		printf("{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32001, \"message\": \"Location not configured\"}, \"id\": %d}\n", id);
	}
}

char *requests = NULL;

static int on_body(llhttp_t *parser, const char *at, size_t length)
{
	if (requests) {
		char *new_requests = realloc((void *)requests, strlen(requests) + length + 1);
		if (!new_requests) {
			return -1; // メモリ不足
		}
		requests = new_requests;
	}
	else {
		requests = malloc(length + 1);
		if (!requests) {
			return -1; // メモリ不足
		}
	}

	strncat((char *)requests, at, length);
	requests[strlen(requests)] = '\0'; // Null-terminate

	return 0;
}

const char parse_error[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}";
const char invalid_request[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}";
const char method_not_found[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}";
const char unknown_tool[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32602,\"message\":\"Unknown tool\"}}";

const char resource[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"logging\":{},\"tools\":{\"listChanged\":true}},\"serverInfo\":{\"name\":\"Raspberry Pi Pico Smart Home\",\"description\":\"A smart home system based on Raspberry Pi Pico.\",\"version\":\"1.0.0.0\"}}}";
const char tool_list[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":[{\"name\":\"switch.set\",\"description\":\"スイッチをONまたはOFFにします。\",\"inputSchema\":{\"title\":\"switch.set\",\"description\":\"スイッチをONまたはOFFにします。\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"state\":{\"type\":\"string\",\"enum\":[\"on\",\"off\"]}},\"required\":[\"switch_id\",\"state\"]}},{\"name\":\"switch.set_location\",\"description\":\"スイッチの設置場所を設定します。\",\"inputSchema\":{\"title\":\"switch.set_location\",\"description\":\"スイッチの設置場所を設定します。\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"}},\"required\":[\"switch_id\",\"location\"]}}]}}";

static int on_message_complete(llhttp_t *parser)
{
	JSON_Value *val = json_parse_string(requests);
	if (!val) {
		response_printf(parse_error, response_id);
		response_id++;
		return 0;
	}

	JSON_Object *obj = json_value_get_object(val);
	const char *method = json_object_get_string(obj, "method");
	int id = (int)json_object_get_number(obj, "id");
	JSON_Object *params = json_object_get_object(obj, "params");

	if (strcmp(method, "initialize") == 0) {
		response_printf(resource, id);
	}
	else if (strcmp(method, "tools/list") == 0) {
		response_printf(tool_list, id);
	}
	else if (strcmp(method, "mcp.set_context") == 0) {
		handle_set_context(params, id);
	}
	else if (strcmp(method, "mcp.call") == 0) {
		handle_call(params, id);
	}
	else {
		response_printf(method_not_found, id);
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
