#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "hardware/flash.h"
#include "lwip/tcp.h"
#include "lwip/apps/mdns.h"
#include "lwip/init.h"
#include "llhttp.h"
#include "parson.h"

#define HTTP_PORT 3001
#define ID_SIZE 22
#define HTTP_NEWLINE "\r\n"
#define SSE_NEWLINE "\n"
#define SSE_SEPARATOR "\n"

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
	char *method;
	char *url;
	char *query;
	enum endpoint_type endpoint_type;
	char *request;
	char *response;
	char sessionId[ID_SIZE + 1];
	struct tcp_pcb *sse_pcb;
	struct session_info *next;      // 次のノードへのポインタ
} session_info_t;

// リストの先頭ポインタ
static session_info_t *head = NULL;
static char hostname[sizeof(CYW43_HOST_NAME) + 4];
static int response_id = 1;
static bool led_on = false;

static int on_method(llhttp_t *parser, const char *at, size_t length);
static int on_method_complete(llhttp_t *parser);
static int on_url(llhttp_t *parser, const char *at, size_t length);
static int on_url_complete(llhttp_t *parser);
static int on_body(llhttp_t *parser, const char *at, size_t length);
static int on_message_complete(llhttp_t *parser);

static const char base64url_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

// 3バイト → 4文字（Base64URL）
void base64url_encode_3bytes(const uint8_t *in, char *out, int len) {
	uint32_t val = 0;
	val |= len > 0 ? in[0] << 16 : 0;
    val |= len > 1 ? in[1] << 8  : 0;
    val |= len > 2 ? in[2]      : 0;

	out[0] = base64url_chars[(val >> 18) & 0x3F];
	out[1] = base64url_chars[(val >> 12) & 0x3F];
	out[2] = (len > 1) ? base64url_chars[(val >> 6) & 0x3F] : '\0';
    out[3] = (len > 2) ? base64url_chars[val & 0x3F]        : '\0';
}

// 16バイト → Base64URL（最大22文字＋null終端）
void base64url_encode_16bytes(const uint8_t *input, char *output) {
	int out_index = 0;
	for (int i = 0; i < 16; i += 3) {
		char temp[4] = { 0 };
		int len = (16 - i >= 3) ? 3 : (16 - i);
		base64url_encode_3bytes(&input[i], temp, len);
		for (int j = 0; j < 4 && temp[j]; ++j) {
			output[out_index++] = temp[j];
		}
	}
	output[out_index] = '\0';
}

void generate_guid(char *output) {
	rng_128_t rand128;
	get_rand_128(&rand128);
	base64url_encode_16bytes((uint8_t *)&rand128, output);
}

#if LWIP_MDNS_RESPONDER
static void srv_txt(struct mdns_service *service, void *txt_userdata)
{
	err_t res;
	LWIP_UNUSED_ARG(txt_userdata);

	res = mdns_resp_add_service_txtitem(service, "path=/", 6);
	LWIP_ERROR("mdns add service txt failed\n", (res == ERR_OK), return);
}
#endif

// Return some characters from the ascii representation of the mac address
// e.g. 112233445566
// chr_off is index of character in mac to start
// chr_len is length of result
// chr_off=8 and chr_len=4 would return "5566"
// Return number of characters put into destination
static size_t get_mac_ascii(int idx, size_t chr_off, size_t chr_len, char *dest_in) {
	static const char hexchr[16] = "0123456789ABCDEF";
	uint8_t mac[8];
	char *dest = dest_in;
	assert(chr_off + chr_len <= (2 * sizeof(mac)));
	flash_get_unique_id(mac);
	for (; chr_len && (chr_off >> 1) < sizeof(mac); ++chr_off, --chr_len) {
		*dest++ = hexchr[mac[chr_off >> 1] >> (4 * (1 - (chr_off & 1))) & 0xf];
	}
	return dest - dest_in;
}

// URLデコード関数（簡易版）
static void url_decode(char *dst, const char *src) {
	char a, b;
	while (*src) {
		if ((*src == '%') &&
			((a = src[1]) && (b = src[2])) &&
			(isxdigit(a) && isxdigit(b))) {
			a = (a >= 'a') ? a - 'a' + 10 : (a >= 'A') ? a - 'A' + 10 : a - '0';
			b = (b >= 'a') ? b - 'a' + 10 : (b >= 'A') ? b - 'A' + 10 : b - '0';
			*dst++ = 16 * a + b;
			src += 3;
		}
		else if (*src == '+') {
			*dst++ = ' ';
			src++;
		}
		else {
			*dst++ = *src++;
		}
	}
	*dst = '\0';
}

// クエリ文字列から指定キーの値を返す関数
static char *get_query_value(const char *query, const char *key) {
	char *query_copy = strdup(query); // 元の文字列を変更しないようにコピー
	char *token = strtok(query_copy, "&");
	size_t key_len = strlen(key);

	while (token) {
		if (strncmp(token, key, key_len) == 0 && token[key_len] == '=') {
			char *value_encoded = token + key_len + 1;
			char *decoded = malloc(strlen(value_encoded) + 1);
			if (decoded) {
				url_decode(decoded, value_encoded);
				free(query_copy);
				return decoded;
			}
		}
		token = strtok(NULL, "&");
	}

	free(query_copy);
	return NULL; // 見つからない場合
}

static void switch_led(const char *val)
{
        if (!val) {
                return;
        }

        if (strcasecmp(val, "on") == 0) {
                led_on = true;
        } else if (strcasecmp(val, "off") == 0) {
                led_on = false;
        }

        cyw43_gpio_set(&cyw43_state, 0, led_on);
}

static void session_info_free(session_info_t *info)
{
	free(info->url);
	free(info->method);
	free(info->request);
	free(info->response);
	free(info);
}

// ノードを末尾に追加
void append_node(session_info_t *new_node) {
	if (!new_node) {
		perror("malloc failed");
		return;
	}

	new_node->next = NULL;

	if (!head) {
		head = new_node;
		return;
	}

	session_info_t *curr = head;
	while (curr->next) {
		curr = curr->next;
	}
	curr->next = new_node;
}

// IDでノードを削除（成功で1、失敗で0）
int delete_node(const char sessionId[ID_SIZE]) {
	session_info_t *curr = head;
	session_info_t *prev = NULL;

	while (curr) {
		if (memcmp(curr->sessionId, sessionId, ID_SIZE) == 0) {
			if (prev) {
				prev->next = curr->next;
			}
			else {
				head = curr->next;
			}
			session_info_free(curr);
			return 1; // 削除成功
		}
		prev = curr;
		curr = curr->next;
	}
	return 0; // 見つからず
}

session_info_t *find_node(const char sessionId[ID_SIZE]) {
	session_info_t *curr = head;

	while (curr) {
		if (memcmp(curr->sessionId, sessionId, ID_SIZE) == 0) {
			return curr;
		}
		curr = curr->next;
	}
	return NULL; // 見つからず
}

const char response_200[] = "HTTP/1.1 200 OK"HTTP_NEWLINE
	"Content-Type: text/event-stream"HTTP_NEWLINE
	"Cache-Control: no-cache,no-store"HTTP_NEWLINE
	"Content-Encoding: identity"HTTP_NEWLINE
	"Connection: keep-alive"HTTP_NEWLINE
	"Transfer-Encoding: chunked"HTTP_NEWLINE HTTP_NEWLINE;
const char response_202[] = "HTTP/1.1 202 Accepted"HTTP_NEWLINE
	"Transfer-Encoding: chunked"HTTP_NEWLINE
	""HTTP_NEWLINE
	"8"HTTP_NEWLINE
	"Accepted"HTTP_NEWLINE
	"0"HTTP_NEWLINE HTTP_NEWLINE;
const char response_400[] = "HTTP/1.1 400 Bad Request"HTTP_NEWLINE HTTP_NEWLINE;
const char response_404[] = "HTTP/1.1 404 Not Found"HTTP_NEWLINE HTTP_NEWLINE;
const char response_405[] = "HTTP/1.1 405 Method Not Allowed"HTTP_NEWLINE
	"Content-Length: 0"HTTP_NEWLINE
	"Allow: GET"HTTP_NEWLINE HTTP_NEWLINE;

static err_t http_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *pbuf, err_t err)
{
	session_info_t *info = (session_info_t *)arg;
	llhttp_t *parser = &info->parser;
	if (pbuf == NULL) {
		if (!delete_node(info->sessionId))
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
		if (info->sse_pcb != NULL) {
			char *chunked_response = malloc(strlen(info->response) + 64);
			if (chunked_response != NULL) {
				int len = sprintf(chunked_response, "%x"HTTP_NEWLINE"%s"HTTP_NEWLINE, (int)strlen(info->response), info->response);
				tcp_write(info->sse_pcb, chunked_response, len, TCP_WRITE_FLAG_COPY);
				free(chunked_response);
			}
		}
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

	memset(info, 0, sizeof(session_info_t));
	info->pcb = newpcb;

	llhttp_t *parser = &info->parser;
	llhttp_settings_t *settings = (llhttp_settings_t *)&info->settings;
	llhttp_settings_init(settings);
	settings->on_method = on_method;
	settings->on_method_complete = on_method_complete;
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
	tcp_bind(pcb, IP_ADDR_ANY, HTTP_PORT);
	pcb = tcp_listen(pcb);
	tcp_accept(pcb, http_accept_cb);
}

int response_printf(session_info_t *info, const char *format, ...)
{
	char header[] = "event: message"SSE_NEWLINE"data: ";
	const char footer[] = SSE_NEWLINE SSE_SEPARATOR;
	va_list args;
	va_start(args, format);
	int len = vsnprintf(NULL, 0, format, args);
	va_end(args);

	if (len < 0) {
		return -1; // エラー
	}

	info->response = malloc(sizeof(header) - 1 + len + sizeof(footer) - 1 + 1);
	if (!info->response) {
		return -1; // メモリ不足
	}

	strcpy(info->response, header);
	va_start(args, format);
	vsnprintf(&info->response[sizeof(header) - 1], len + 1, format, args);
	va_end(args);
	strcat(info->response, footer);

	return len;
}

const char invalid_request[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32600,\"message\":\"Invalid Request\"}}";
const char method_not_found[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32601,\"message\":\"Method not found\"}}";
const char location_not_configured[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32001, \"message\": \"Location not configured\"}, \"id\": %d}";
const char unknown_tool[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32602,\"message\":\"Unknown tool\"}}";
const char invalid_protocol[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32602,\"message\":\"Invalid protocol version\"}}";
const char invalid_context[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Invalid context\"}, \"id\": %d}";
const char missing_fields[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing fields\"}, \"id\": %d}";
const char missing_call_arguments[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing call arguments\"}, \"id\": %d}";
const char parse_error[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}";

const char resource[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"logging\":{},\"tools\":{\"listChanged\":true}},\"serverInfo\":{\"name\":\"Raspberry Pi Pico Smart Home\",\"description\":\"A smart home system based on Raspberry Pi Pico.\",\"version\":\"1.0.0.0\"}}}";
const char tool_list[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":["
		"{\"name\":\"set_switch\",\"description\":\"Use this to toggle a light or other switch ON or OFF.\",\"inputSchema\":{\"title\":\"set_switch\",\"description\":\"Use this to toggle a light or other switch ON or OFF.\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"},\"state\":{\"type\":\"string\",\"enum\":[\"on\",\"off\"]}},\"required\":[\"state\"]}},"
		"{\"name\":\"set_location\",\"description\":\"Set the location of the switch.\",\"inputSchema\":{\"title\":\"set_location\",\"description\":\"Set the location of the switch.\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"}},\"required\":[\"location\"]}},"
		"{\"name\":\"set_switch_id\",\"description\":\"Set the ID of the switch.\",\"inputSchema\":{\"title\":\"set_switch_id\",\"description\":\"Set the ID of the switch.\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"}},\"required\":[\"switch_id\"]}}"
	"]}}";
const char status_ok[] = "{\"jsonrpc\": \"2.0\", \"result\": {\"status\": \"ok\"}, \"id\": %d}\n";
const char call_success[] = "{\"jsonrpc\": \"2.0\", \"result\": {\"success\": true, \"location\": \"%s\", \"switch_id\": \"%s\", \"state\": \"%s\"}, \"id\": %d}";

// コンテキスト保持（簡易構造体）
typedef struct
{
	char location[32];
	char switch_id[128];
} SwitchServerContext;

SwitchServerContext context;

void handle_set_location(session_info_t *info, JSON_Object *arguments, int id)
{
	const char *location = json_object_get_string(arguments, "location");

	if (location) {
		strncpy(context.location, location, sizeof(context.location));
		response_printf(info, status_ok, id);
	}
	else {
		response_printf(info, missing_fields, id);
	}
}

void handle_set_switch_id(session_info_t *info, JSON_Object *arguments, int id)
{
	const char *switch_id = json_object_get_string(arguments, "switch_id");

	if (switch_id) {
		strncpy(context.switch_id, switch_id, sizeof(context.switch_id));
		response_printf(info, status_ok, id);
	}
	else {
		response_printf(info, missing_fields, id);
	}
}

void handle_set_switch(session_info_t *info, JSON_Object *arguments, int id)
{
	const char *location = json_object_get_string(arguments, "location");
	const char *switch_id = json_object_get_string(arguments, "switch_id");
	const char *state = json_object_get_string(arguments, "state");

	if (!state) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	if ((location && strcmp(location, context.location) == 0)
		|| (switch_id && strcmp(switch_id, context.switch_id) == 0)
		|| (!location && !switch_id)) {
		switch_led(state);
		response_printf(info, call_success, context.location, context.switch_id, state, id);
	}
	else {
		response_printf(info, location_not_configured, id);
	}
}

static int on_method(llhttp_t *parser, const char *at, size_t length)
{
	session_info_t *info = (session_info_t *)parser;
	size_t len;
	if (info->method) {
		len = strlen(info->method) + length + 1;
		char *new_requests = realloc((void *)info->method, len);
		if (!new_requests) {
			return -1; // メモリ不足
		}
		info->method = new_requests;
		strncat((char *)info->method, at, length);
	}
	else {
		len = length + 1;
		info->method = malloc(len);
		if (!info->method) {
			return -1; // メモリ不足
		}
		strncpy((char *)info->method, at, length);
	}

	info->method[len - 1] = '\0'; // Null-terminate

	return 0;
}

static int on_method_complete(llhttp_t *parser)
{
	session_info_t *info = (session_info_t *)parser;

	if (strcmp(info->method, "GET") != 0 && strcmp(info->method, "POST") != 0) {
		tcp_write(info->pcb, response_404, strlen(response_404), TCP_WRITE_FLAG_COPY);
		return -1; // メソッドがサポートされていない
	}

	return 0; // 成功
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
	char *sessionId;
	session_info_t *sse = NULL;

	switch (info->endpoint_type) {
	case ENDPOINT_SSE:
		if (strcmp(info->method, "POST") == 0) {
			tcp_write(info->pcb, response_405, strlen(response_405), TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
		}
		else {
			generate_guid(info->sessionId);
			info->sse_pcb = info->pcb; // SSE用のPCBを保存
			append_node(info);
			char rpc[127] = { 0 };
			int len = snprintf(rpc, sizeof(rpc), "event: endpoint"SSE_NEWLINE"data: /message?sessionId=%s"SSE_NEWLINE SSE_SEPARATOR, info->sessionId);
			char response[512] = { 0 };
			len = snprintf(response, sizeof(response), "%s%x"HTTP_NEWLINE"%s"HTTP_NEWLINE, response_200, strlen(rpc), rpc);
			tcp_write(info->pcb, response, strlen(response), TCP_WRITE_FLAG_COPY);
		}
		break;
	case ENDPOINT_MESSAGE:
	case ENDPOINT_EVENT:
		sessionId = get_query_value(info->query, "sessionId");
		if (sessionId) {
			sse = find_node(sessionId);
			free(sessionId);
		}
		if (sse) {
			info->sse_pcb = sse->pcb; // PCBを更新
			tcp_write(info->pcb, response_202, strlen(response_202), TCP_WRITE_FLAG_COPY);
		}
		else {
			tcp_write(info->pcb, response_400, strlen(response_400), TCP_WRITE_FLAG_COPY);
		}
		break;
	case ENDPOINT_NOT_FOUND:
		tcp_write(info->pcb, response_404, strlen(response_404), TCP_WRITE_FLAG_COPY);
		break;
	}

	if (info->request == NULL || strlen(info->request) == 0) {
		return 0;
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
	JSON_Object *arguments = json_object_get_object(params, "arguments");

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
		if (strcmp(name, "set_location") == 0) {
			handle_set_location(info, arguments, id);
		}
		else if (strcmp(name, "set_switch_id") == 0) {
			handle_set_switch_id(info, arguments, id);
		}
		else if (strcmp(name, "set_switch") == 0) {
			handle_set_switch(info, arguments, id);
		}
	}
	else {
		response_printf(info, method_not_found, id);
	}

	json_value_free(val);

	return 0;
}

int loop()
{
	// Enable wifi station
	cyw43_arch_enable_sta_mode();
	netif_set_hostname(&cyw43_state.netif[CYW43_ITF_STA], hostname);

	printf("Connecting to Wi-Fi(%s)...\n", WIFI_SSID);
	if (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASSWORD, CYW43_AUTH_WPA2_AES_PSK, 30000)) {
		printf("failed to connect.\n");
		return 1;
	}
	else {
		printf("Connected.\n");
		// Read the ip address in a human readable way
		uint8_t *ip_address = (uint8_t *)&(cyw43_state.netif[0].ip_addr.addr);
		printf("IP address %d.%d.%d.%d\n", ip_address[0], ip_address[1], ip_address[2], ip_address[3]);
		printf("Hostname %s\n", hostname);
	}

#if LWIP_MDNS_RESPONDER
	// Setup mdns
	cyw43_arch_lwip_begin();
	mdns_resp_init();
	printf("mdns host name %s.local\n", hostname);
#if LWIP_VERSION_MAJOR >= 2 && LWIP_VERSION_MINOR >= 2
	mdns_resp_add_netif(&cyw43_state.netif[CYW43_ITF_STA], hostname);
	mdns_resp_add_service(&cyw43_state.netif[CYW43_ITF_STA], "pico_httpd", "_http", DNSSD_PROTO_TCP, HTTP_PORT, srv_txt, NULL);
#else
	mdns_resp_add_netif(&cyw43_state.netif[CYW43_ITF_STA], hostname, 60);
	mdns_resp_add_service(&cyw43_state.netif[CYW43_ITF_STA], "pico_httpd", "_http", DNSSD_PROTO_TCP, HTTP_PORT, 60, srv_txt, NULL);
#endif
	cyw43_arch_lwip_end();
#endif

	http_server_init();
	printf("HTTP server initialized.\n");

	while (true) {
		sleep_ms(1000);
	}
#if LWIP_MDNS_RESPONDER
	mdns_resp_remove_netif(&cyw43_state.netif[CYW43_ITF_STA]);
#endif
}

int main()
{
	stdio_init_all();

	memcpy(&hostname[0], CYW43_HOST_NAME, sizeof(CYW43_HOST_NAME) - 1);
	get_mac_ascii(CYW43_HAL_MAC_WLAN0, 8, 4, &hostname[sizeof(CYW43_HOST_NAME) - 1]);
	hostname[sizeof(hostname) - 1] = '\0';

	//while(!stdio_usb_connected())
	//	__asm("WFI");

	// Initialise the Wi-Fi chip
	if (cyw43_arch_init()) {
		printf("Wi-Fi init failed\n");
		return -1;
	}

	while (true) {
		loop();
	}

	cyw43_arch_deinit();
}