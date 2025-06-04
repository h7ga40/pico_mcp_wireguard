#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/tcp.h"
#include "llhttp.h"
#include "parson.h"

static struct tcp_pcb *sse_pcb = NULL;
const char *url = NULL;

static int on_url(llhttp_t *parser, const char *at, size_t length)
{
	free((void *)url); // 前のURLを解放
	url = strndup(at, length);
}

static err_t http_recv_cb(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err)
{
	if (!p)
		return ERR_OK;

	char *data = malloc(p->tot_len + 1);
	pbuf_copy_partial(p, data, p->tot_len, 0);
	data[p->tot_len] = '\0';
	pbuf_free(p);

	llhttp_t parser;
	llhttp_settings_t settings;
	llhttp_settings_init(&settings);
	settings.on_url = on_url;

	// パースしてURIを見る
	llhttp_init(&parser, HTTP_REQUEST, &settings);
	llhttp_execute(&parser, data, strlen(data));

	if (strcmp(url, "/sse") == 0) {
		const char *response =
			"HTTP/1.1 200 OK\r\n"
			"Content-Type: text/event-stream\r\n"
			"Cache-Control: no-cache\r\n"
			"Connection: keep-alive\r\n\r\n";

		tcp_write(tpcb, response, strlen(response), TCP_WRITE_FLAG_COPY);
		sse_pcb = tpcb; // 接続保持
	}
	else if (strcmp(url, "/message") == 0 && sse_pcb) {
		const char *msg = "data: Hello from /message\n\n";
		tcp_write(sse_pcb, msg, strlen(msg), TCP_WRITE_FLAG_COPY);
	}
	else if (strcmp(url, "/event") == 0 && sse_pcb) {
		const char *msg = "event: custom\ndata: Event fired!\n\n";
		tcp_write(sse_pcb, msg, strlen(msg), TCP_WRITE_FLAG_COPY);
	}
	else {
		const char *res404 = "HTTP/1.1 404 Not Found\r\n\r\n";
		tcp_write(tpcb, res404, strlen(res404), TCP_WRITE_FLAG_COPY);
	}

	free(data);
	return ERR_OK;
}

static err_t http_accept_cb(void *arg, struct tcp_pcb *newpcb, err_t err)
{
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
		printf("{\"jsonrpc\": \"2.0\", \"result\": {\"success\": true, \"url\": \"%s\", \"switch_id\": \"%s\", \"state\": \"%s\"}, \"id\": %d}\n",
			context.url, switch_id, state, id);
	}
	else {
		printf("{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32001, \"message\": \"Location not configured\"}, \"id\": %d}\n", id);
	}
}

int test(const char *requests)
{
	JSON_Value *val = json_parse_string(requests);
	if (!val)
		return -1;

	JSON_Object *obj = json_value_get_object(val);
	const char *method = json_object_get_string(obj, "method");
	int id = (int)json_object_get_number(obj, "id");
	JSON_Object *params = json_object_get_object(obj, "params");

	if (strcmp(method, "mcp.set_context") == 0) {
		handle_set_context(params, id);
	}
	else if (strcmp(method, "mcp.call") == 0) {
		handle_call(params, id);
	}
	else {
		printf("{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32601, \"message\": \"Method not found\"}, \"id\": %d}\n", id);
	}

	json_value_free(val);

	return 0;
}

// JSON-RPC リクエスト（1: set_context, 2: call）
const char *requests[] = {
	// リクエスト1: context 設定
	"{ \"jsonrpc\": \"2.0\", \"method\": \"mcp.set_context\", \"params\": { \"context\": { \"switch_servers\": { \"servers\": [ { \"location\": \"kitchen\", \"url\": \"http://192.168.1.101:8080\" } ] } } }, \"id\": 1 }",
	// リクエスト2: 実行
	"{ \"jsonrpc\": \"2.0\", \"method\": \"mcp.call\", \"params\": { \"function\": \"switch_control.set_state\", \"switch_id\": \"main_light\", \"state\": \"on\", \"location\": \"kitchen\" }, \"id\": 2 }"
};

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

	int i = 0;
	while (true) {
		test(requests[i]);
		i = i + 1 % 2;

		sleep_ms(1000);
	}
}
