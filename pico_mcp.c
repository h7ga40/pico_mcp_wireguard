#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdarg.h>
#include <stdlib.h>
#include <ctype.h>

#include "pico/stdlib.h"
#include "pico/binary_info.h"
#include "pico/critical_section.h"
#include "pico/util/queue.h"
#include "pico/multicore.h"
#include "hardware/flash.h"
#include "hardware/clocks.h"

#include "bsp/board.h"
#include "tusb.h"

#include "wizchip_conf.h"
#include "socket.h"
#include "w5x00_spi.h"
#include "w5x00_lwip.h"

#include "wireguardif.h"

#include "lwip/init.h"
#include "lwip/netif.h"
#include "lwip/timeouts.h"

#include "lwip/apps/fs.h"
#include "lwip/apps/lwiperf.h"
#include "lwip/etharp.h"
#include "lwip/tcp.h"
#include "lwip/udp.h"
#include "lwip/dhcp.h"
#include "lwip/dns.h"

#include "llhttp.h"
#include "parson.h"

#include "argument_definitions.h"
#include "usb_hid_reports.h"

#define PLL_SYS_KHZ (133 * 1000)

static struct netif wg_netif_struct = {0};
static struct netif *wg_netif = NULL;
static uint8_t wireguard_peer_index = WIREGUARDIF_INVALID_INDEX;
static bool enable_dhcp = ENABLE_DHCP;

/* Socket */
#define SOCKET_MACRAW 0
/* Port */
#define PORT_LWIPERF 5001

//#define STRINGIFY(x) #x
#define STRINGIFY(x) x
#define TO_STRING(x) STRINGIFY(x)
#define SPLIT_MAC(mac) STRINGIFY(mac)

#define HTTP_PORT 3001
#define ID_SIZE 22
#define HTTP_NEWLINE "\r\n"
#define SSE_NEWLINE "\n"
#define SSE_SEPARATOR "\n"
#define WOL_MAGIC_PACKET_LEN 102

#ifndef WOL_RATE_LIMIT_MS
#define WOL_RATE_LIMIT_MS 30000
#endif

#ifndef WOL_ARP_DEFAULT_TIMEOUT_MS
#define WOL_ARP_DEFAULT_TIMEOUT_MS 1000
#endif

enum endpoint_type {
	ENDPOINT_NONE,
	ENDPOINT_SSE,
	ENDPOINT_MESSAGE,
	ENDPOINT_EVENT,
	ENDPOINT_KBD,
	ENDPOINT_WOL,
	ENDPOINT_WOL_ALLOWLIST,
	ENDPOINT_WOL_SEND,
	ENDPOINT_WOL_PROBE,
	ENDPOINT_WOL_SEND_AND_PROBE,
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

/* Ethernet */
struct netif g_netif;

// リストの先頭ポインタ
static session_info_t *head = NULL;
static int response_id = 1;
static critical_section_t g_pwr_pulse_cs;
static bool g_pwr_pulse_in_progress = false;
static absolute_time_t g_wol_last_sent;
static bool g_wol_last_sent_valid = false;

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

extern const struct fsdata_file file_wol_allowlist_json[];
static const struct fsdata_file *wol_allowlist_file = file_wol_allowlist_json;

static bool wol_get_allowlist_json(const char **out_json, size_t *out_len)
{
	if (!wol_allowlist_file || !wol_allowlist_file->data || wol_allowlist_file->len <= 0) {
		return false;
	}

	const unsigned char *data = wol_allowlist_file->data;
	int len = wol_allowlist_file->len;
	const unsigned char *body = data;
	int header_end = -1;

	for (int i = 0; i + 3 < len; i++) {
		if (data[i] == '\r' && data[i + 1] == '\n' &&
			data[i + 2] == '\r' && data[i + 3] == '\n') {
			header_end = i + 4;
			break;
		}
	}

	if (header_end >= 0 && header_end < len) {
		body = data + header_end;
		len -= header_end;
	}

	*out_json = (const char *)body;
	*out_len = (size_t)len;
	return true;
}

static bool wol_parse_mac(const char *mac_str, uint8_t out_mac[6])
{
	if (!mac_str) return false;

	char hexbuf[13] = { 0 };
	int hexlen = 0;

	for (const char *p = mac_str; *p; p++) {
		if (isxdigit((unsigned char)*p)) {
			if (hexlen >= 12) return false;
			hexbuf[hexlen++] = (char)toupper((unsigned char)*p);
		} else if (*p == ':' || *p == '-') {
			continue;
		} else {
			return false;
		}
	}

	if (hexlen != 12) return false;

	for (int i = 0; i < 6; i++) {
		char hi = hexbuf[i * 2];
		char lo = hexbuf[i * 2 + 1];
		int h = (hi >= 'A') ? (hi - 'A' + 10) : (hi - '0');
		int l = (lo >= 'A') ? (lo - 'A' + 10) : (lo - '0');
		out_mac[i] = (uint8_t)((h << 4) | l);
	}

	return true;
}

static bool wol_rate_limited(uint32_t *retry_ms_out)
{
	if (!g_wol_last_sent_valid) return false;

	absolute_time_t now = get_absolute_time();
	int64_t diff_us = absolute_time_diff_us(g_wol_last_sent, now);
	if (diff_us < 0) diff_us = 0;

	int64_t limit_us = (int64_t)WOL_RATE_LIMIT_MS * 1000;
	if (diff_us >= limit_us) return false;

	if (retry_ms_out) {
		*retry_ms_out = (uint32_t)((limit_us - diff_us + 999) / 1000);
	}
	return true;
}

static void wol_mark_sent(void)
{
	g_wol_last_sent = get_absolute_time();
	g_wol_last_sent_valid = true;
}

static void wol_default_broadcast_ip(ip_addr_t *out_ip)
{
	ip4_addr_t ip4 = *netif_ip4_addr(&g_netif);
	ip4_addr_t mask4 = *netif_ip4_netmask(&g_netif);

	if (ip4_addr_isany_val(ip4) || ip4_addr_isany_val(mask4)) {
		ipaddr_aton("255.255.255.255", out_ip);
		return;
	}

	ip4_addr_t bcast;
	bcast.addr = ip4.addr | ~mask4.addr;
	ip_addr_copy_from_ip4(*out_ip, bcast);
}

static bool wol_send_magic_packet(const uint8_t mac[6], const ip_addr_t *dst_ip, uint16_t port)
{
	struct udp_pcb *pcb = udp_new();
	if (!pcb) return false;

	udp_set_flags(pcb, SOF_BROADCAST);

	struct pbuf *p = pbuf_alloc(PBUF_TRANSPORT, WOL_MAGIC_PACKET_LEN, PBUF_RAM);
	if (!p) {
		udp_remove(pcb);
		return false;
	}

	uint8_t *payload = (uint8_t *)p->payload;
	memset(payload, 0xFF, 6);
	for (int i = 0; i < 16; i++) {
		memcpy(payload + 6 + (i * 6), mac, 6);
	}

	err_t err = udp_sendto_if(pcb, p, dst_ip, port, &g_netif);
	pbuf_free(p);
	udp_remove(pcb);

	return (err == ERR_OK);
}

static bool wol_send_magic_packet_2(const uint8_t mac[6])
{
	if (!g_netif.linkoutput) return false;

	uint8_t frame[14 + WOL_MAGIC_PACKET_LEN];
	uint8_t *payload = frame + 14;
	uint8_t dest_mac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

	memcpy(frame, dest_mac, 6);
	memcpy(frame + 6, g_netif.hwaddr, 6);
	frame[12] = 0x08; // EtherType 0x0842 (Wake-on-LAN)
	frame[13] = 0x42;

	memset(payload, 0xFF, 6);
	for (int i = 0; i < 16; i++) {
		memcpy(payload + 6 + (i * 6), mac, 6);
	}

	struct pbuf *p = pbuf_alloc(PBUF_RAW, sizeof(frame), PBUF_RAM);
	if (!p) return false;

	pbuf_take(p, frame, sizeof(frame));
	err_t err = g_netif.linkoutput(&g_netif, p);
	pbuf_free(p);

	return (err == ERR_OK);
}

static bool wol_arp_probe_internal(const ip_addr_t *ip, uint32_t timeout_ms, const char **reason_out)
{
	if (!netif_is_up(&g_netif) || !netif_is_link_up(&g_netif)) {
		if (reason_out) *reason_out = "netif down";
		return false;
	}

	err_t req_err = etharp_request(&g_netif, ip_2_ip4(ip));
	if (req_err != ERR_OK) {
		if (reason_out) *reason_out = "request failed";
		return false;
	}

	absolute_time_t start = get_absolute_time();
	while (absolute_time_diff_us(start, get_absolute_time()) < (int64_t)timeout_ms * 1000) {
		struct eth_addr *eth_ret = NULL;
		const ip4_addr_t *ip_ret = NULL;
		if (etharp_find_addr(&g_netif, ip_2_ip4(ip), &eth_ret, &ip_ret) >= 0) {
			if (reason_out) *reason_out = NULL;
			return true;
		}
		sleep_ms(10);
	}

	if (reason_out) *reason_out = "timeout";
	return false;
}

static bool wol_allowlist_match(const char *mac_str, const char *ip_str, bool require_pair, char *err, size_t err_len)
{
	uint8_t mac[6] = { 0 };
	ip_addr_t ip;
	bool has_mac = false;
	bool has_ip = false;

	if (mac_str && mac_str[0] != '\0') {
		if (!wol_parse_mac(mac_str, mac)) {
			snprintf(err, err_len, "invalid mac");
			return false;
		}
		has_mac = true;
	}

	if (ip_str && ip_str[0] != '\0') {
		if (!ipaddr_aton(ip_str, &ip)) {
			snprintf(err, err_len, "invalid ip");
			return false;
		}
		has_ip = true;
	}

	if (require_pair && (!has_mac || !has_ip)) {
		snprintf(err, err_len, "missing fields");
		return false;
	}

	if (!has_mac && !has_ip) {
		snprintf(err, err_len, "missing fields");
		return false;
	}

	const char *json_data = NULL;
	size_t json_len = 0;
	if (!wol_get_allowlist_json(&json_data, &json_len) || json_len == 0) {
		snprintf(err, err_len, "allowlist unavailable");
		return false;
	}

	char *json_buf = malloc(json_len + 1);
	if (!json_buf) {
		snprintf(err, err_len, "no memory");
		return false;
	}
	memcpy(json_buf, json_data, json_len);
	json_buf[json_len] = '\0';

	JSON_Value *val = json_parse_string(json_buf);
	free(json_buf);
	if (!val) {
		snprintf(err, err_len, "allowlist parse error");
		return false;
	}

	JSON_Array *arr = json_value_get_array(val);
	if (!arr) {
		json_value_free(val);
		snprintf(err, err_len, "allowlist invalid");
		return false;
	}

	bool require_both = require_pair || (has_mac && has_ip);

	for (size_t i = 0; i < json_array_get_count(arr); i++) {
		JSON_Object *entry = json_array_get_object(arr, i);
		if (!entry) continue;

		const char *entry_mac_str = json_object_get_string(entry, "mac");
		const char *entry_ip_str = json_object_get_string(entry, "ip");

		bool mac_ok = true;
		bool ip_ok = true;

		if (has_mac) {
			uint8_t entry_mac[6] = { 0 };
			if (!entry_mac_str || !wol_parse_mac(entry_mac_str, entry_mac)) {
				mac_ok = false;
			} else if (memcmp(entry_mac, mac, 6) != 0) {
				mac_ok = false;
			}
		}

		if (has_ip) {
			ip_addr_t entry_ip;
			if (!entry_ip_str || !ipaddr_aton(entry_ip_str, &entry_ip)) {
				ip_ok = false;
			} else if (!ip_addr_cmp(&entry_ip, &ip)) {
				ip_ok = false;
			}
		}

		if (require_both) {
			if (mac_ok && ip_ok) {
				json_value_free(val);
				return true;
			}
		} else {
			if ((has_mac && mac_ok) || (has_ip && ip_ok)) {
				json_value_free(val);
				return true;
			}
		}
	}

	json_value_free(val);
	snprintf(err, err_len, "not allowed");
	return false;
}

static void http_send_json(session_info_t *info, int status_code, const char *json_body)
{
	const char *status = "200 OK";
	if (status_code == 400) status = "400 Bad Request";
	else if (status_code == 403) status = "403 Forbidden";
	else if (status_code == 404) status = "404 Not Found";
	else if (status_code == 405) status = "405 Method Not Allowed";
	else if (status_code == 429) status = "429 Too Many Requests";

	int body_len = (int)strlen(json_body);
	char header[160];
	int header_len = snprintf(header, sizeof(header),
		"HTTP/1.1 %s\r\n"
		"Content-Type: application/json\r\n"
		"Content-Length: %d\r\n"
		"Connection: close\r\n\r\n",
		status, body_len);

	tcp_write(info->pcb, header, header_len, TCP_WRITE_FLAG_COPY);
	tcp_write(info->pcb, json_body, body_len, TCP_WRITE_FLAG_COPY);
}

static bool wol_get_port_from_json(JSON_Object *obj, uint16_t *port_out, char *err, size_t err_len)
{
	uint16_t port = 9;
	if (json_object_has_value_of_type(obj, "port", JSONNumber)) {
		double p = json_object_get_number(obj, "port");
		if (p != 0 && p != 7 && p != 9) {
			snprintf(err, err_len, "invalid port");
			return false;
		}
		port = (uint16_t)p;
	}
	*port_out = port;
	return true;
}

static uint32_t wol_get_timeout_from_json(JSON_Object *obj)
{
	if (json_object_has_value_of_type(obj, "timeout_ms", JSONNumber)) {
		double t = json_object_get_number(obj, "timeout_ms");
		if (t >= 0) {
			return (uint32_t)t;
		}
	}
	return WOL_ARP_DEFAULT_TIMEOUT_MS;
}

static bool wol_send_core(const char *mac_str, const char *broadcast_ip_str, uint16_t port, char *err, size_t err_len)
{
	if (port != 0 && port != 7 && port != 9) {
		snprintf(err, err_len, "invalid port");
		return false;
	}

	if (!wol_allowlist_match(mac_str, NULL, false, err, err_len)) {
		return false;
	}

	uint32_t retry_ms = 0;
	if (wol_rate_limited(&retry_ms)) {
		snprintf(err, err_len, "rate limited (%ums)", (unsigned int)retry_ms);
		return false;
	}

	uint8_t mac[6] = { 0 };
	if (!wol_parse_mac(mac_str, mac)) {
		snprintf(err, err_len, "invalid mac");
		return false;
	}

	if (port == 0) {
		if (!wol_send_magic_packet_2(mac)) {
			snprintf(err, err_len, "send failed");
			return false;
		}
	}
	else {
		ip_addr_t dst_ip;
		if (broadcast_ip_str && broadcast_ip_str[0] != '\0') {
			if (!ipaddr_aton(broadcast_ip_str, &dst_ip)) {
				snprintf(err, err_len, "invalid broadcast ip");
				return false;
			}
		} else {
			wol_default_broadcast_ip(&dst_ip);
		}
	
		if (!wol_send_magic_packet(mac, &dst_ip, port)) {
			snprintf(err, err_len, "send failed");
			return false;
		}
	}

	wol_mark_sent();
	return true;
}

static bool wol_arp_probe_core(const char *ip_str, uint32_t timeout_ms, bool *arp_ok_out, const char **reason_out, char *err, size_t err_len)
{
	if (!wol_allowlist_match(NULL, ip_str, false, err, err_len)) {
		return false;
	}

	ip_addr_t ip;
	if (!ipaddr_aton(ip_str, &ip)) {
		snprintf(err, err_len, "invalid ip");
		return false;
	}

	if (timeout_ms == 0) {
		timeout_ms = WOL_ARP_DEFAULT_TIMEOUT_MS;
	}

	bool ok = wol_arp_probe_internal(&ip, timeout_ms, reason_out);
	if (arp_ok_out) *arp_ok_out = ok;
	return true;
}

static bool wol_send_and_probe_core(const char *mac_str, const char *ip_str, const char *broadcast_ip_str,
	uint16_t port, uint32_t timeout_ms, bool *arp_ok_out, const char **reason_out, char *err, size_t err_len)
{
	if (!wol_allowlist_match(mac_str, ip_str, true, err, err_len)) {
		return false;
	}

	if (!wol_send_core(mac_str, broadcast_ip_str, port, err, err_len)) {
		return false;
	}

	return wol_arp_probe_core(ip_str, timeout_ms, arp_ok_out, reason_out, err, err_len);
}

static void wol_http_send(session_info_t *info)
{
	bool free_request = true;
	if (strcmp(info->method, "POST") != 0) {
		http_send_json(info, 405, "{\"ok\":false,\"error\":\"method not allowed\"}");
		goto cleanup;
	}

	if (!info->request || strlen(info->request) == 0) {
		http_send_json(info, 400, "{\"ok\":false,\"error\":\"missing body\"}");
		goto cleanup;
	}

	JSON_Value *val = json_parse_string(info->request);
	if (!val) {
		http_send_json(info, 400, "{\"ok\":false,\"error\":\"invalid json\"}");
		goto cleanup;
	}

	JSON_Object *obj = json_value_get_object(val);
	if (!obj) {
		json_value_free(val);
		http_send_json(info, 400, "{\"ok\":false,\"error\":\"invalid json\"}");
		goto cleanup;
	}
	const char *mac = json_object_get_string(obj, "mac");
	const char *broadcast_ip = json_object_get_string(obj, "broadcast_ip");
	uint16_t port = 9;
	char err[64] = { 0 };
	bool ok = false;

	if (mac && wol_get_port_from_json(obj, &port, err, sizeof(err))) {
		ok = wol_send_core(mac, broadcast_ip, port, err, sizeof(err));
	} else if (!mac) {
		snprintf(err, sizeof(err), "missing fields");
	}

	if (ok) {
		http_send_json(info, 200, "{\"ok\":true}");
	} else {
		char body[128];
		snprintf(body, sizeof(body), "{\"ok\":false,\"error\":\"%s\"}", err[0] ? err : "failed");
		http_send_json(info, (strncmp(err, "not allowed", 11) == 0) ? 403 : 400, body);
	}

	json_value_free(val);
cleanup:
	if (free_request && info->request) {
		free(info->request);
		info->request = NULL;
	}
}

static void wol_http_probe(session_info_t *info)
{
	bool free_request = true;
	if (strcmp(info->method, "POST") != 0) {
		http_send_json(info, 405, "{\"checked\":false,\"error\":\"method not allowed\"}");
		goto cleanup;
	}

	if (!info->request || strlen(info->request) == 0) {
		http_send_json(info, 400, "{\"checked\":false,\"error\":\"missing body\"}");
		goto cleanup;
	}

	JSON_Value *val = json_parse_string(info->request);
	if (!val) {
		http_send_json(info, 400, "{\"checked\":false,\"error\":\"invalid json\"}");
		goto cleanup;
	}

	JSON_Object *obj = json_value_get_object(val);
	if (!obj) {
		json_value_free(val);
		http_send_json(info, 400, "{\"checked\":false,\"error\":\"invalid json\"}");
		goto cleanup;
	}
	const char *ip = json_object_get_string(obj, "ip");
	uint32_t timeout_ms = wol_get_timeout_from_json(obj);
	char err[64] = { 0 };
	const char *reason = NULL;
	bool arp_ok = false;

	if (ip) {
		if (wol_arp_probe_core(ip, timeout_ms, &arp_ok, &reason, err, sizeof(err))) {
			char body[160];
			if (arp_ok) {
				snprintf(body, sizeof(body), "{\"checked\":true,\"arp_ok\":true}");
			} else {
				snprintf(body, sizeof(body), "{\"checked\":true,\"arp_ok\":false,\"reason\":\"%s\"}", reason ? reason : "timeout");
			}
			http_send_json(info, 200, body);
		} else {
			char body[128];
			snprintf(body, sizeof(body), "{\"checked\":false,\"error\":\"%s\"}", err[0] ? err : "failed");
			http_send_json(info, (strncmp(err, "not allowed", 11) == 0) ? 403 : 400, body);
		}
	} else {
		http_send_json(info, 400, "{\"checked\":false,\"error\":\"missing fields\"}");
	}

	json_value_free(val);
cleanup:
	if (free_request && info->request) {
		free(info->request);
		info->request = NULL;
	}
}

static void wol_http_send_and_probe(session_info_t *info)
{
	bool free_request = true;
	if (strcmp(info->method, "POST") != 0) {
		http_send_json(info, 405, "{\"wol_sent\":false,\"error\":\"method not allowed\"}");
		goto cleanup;
	}

	if (!info->request || strlen(info->request) == 0) {
		http_send_json(info, 400, "{\"wol_sent\":false,\"error\":\"missing body\"}");
		goto cleanup;
	}

	JSON_Value *val = json_parse_string(info->request);
	if (!val) {
		http_send_json(info, 400, "{\"wol_sent\":false,\"error\":\"invalid json\"}");
		goto cleanup;
	}

	JSON_Object *obj = json_value_get_object(val);
	if (!obj) {
		json_value_free(val);
		http_send_json(info, 400, "{\"wol_sent\":false,\"error\":\"invalid json\"}");
		goto cleanup;
	}
	const char *mac = json_object_get_string(obj, "mac");
	const char *ip = json_object_get_string(obj, "ip");
	const char *broadcast_ip = json_object_get_string(obj, "broadcast_ip");
	uint16_t port = 9;
	uint32_t timeout_ms = wol_get_timeout_from_json(obj);
	char err[64] = { 0 };

	if (!mac || !ip) {
		http_send_json(info, 400, "{\"wol_sent\":false,\"error\":\"missing fields\"}");
		json_value_free(val);
		goto cleanup;
	}

	if (!wol_get_port_from_json(obj, &port, err, sizeof(err))) {
		char body[128];
		snprintf(body, sizeof(body), "{\"wol_sent\":false,\"error\":\"%s\"}", err);
		http_send_json(info, 400, body);
		json_value_free(val);
		goto cleanup;
	}

	const char *reason = NULL;
	bool arp_ok = false;
	if (wol_send_and_probe_core(mac, ip, broadcast_ip, port, timeout_ms, &arp_ok, &reason, err, sizeof(err))) {
		char body[180];
		if (arp_ok) {
			snprintf(body, sizeof(body), "{\"wol_sent\":true,\"arp_checked\":true,\"arp_ok\":true}");
		} else {
			snprintf(body, sizeof(body), "{\"wol_sent\":true,\"arp_checked\":true,\"arp_ok\":false,\"reason\":\"%s\"}", reason ? reason : "timeout");
		}
		http_send_json(info, 200, body);
	} else {
		char body[128];
		snprintf(body, sizeof(body), "{\"wol_sent\":false,\"error\":\"%s\"}", err[0] ? err : "failed");
		http_send_json(info, (strncmp(err, "not allowed", 11) == 0) ? 403 : 400, body);
	}

	json_value_free(val);
cleanup:
	if (free_request && info->request) {
		free(info->request);
		info->request = NULL;
	}
}

static bool atx_power_pulse(uint32_t pulse_ms)
{
	bool do_pulse = false;

	critical_section_enter_blocking(&g_pwr_pulse_cs);
	if (!g_pwr_pulse_in_progress) {
		g_pwr_pulse_in_progress = true;
		do_pulse = true;
	}
	critical_section_exit(&g_pwr_pulse_cs);

	if (!do_pulse) {
		return false;
	}

	const bool active_level = (ATX_PWR_ACTIVE_LEVEL != 0);
	const bool idle_level = !active_level;

	gpio_put(ATX_PWR_GPIO, active_level);
	sleep_ms(pulse_ms);
	gpio_put(ATX_PWR_GPIO, idle_level);

	critical_section_enter_blocking(&g_pwr_pulse_cs);
	g_pwr_pulse_in_progress = false;
	critical_section_exit(&g_pwr_pulse_cs);

	return true;
}

const char *get_switch_state()
{
	const bool active_level = (PWR_LED_ACTIVE_LEVEL != 0);
	const bool level = gpio_get(PWR_LED_GPIO);
	return (level == active_level) ? "on" : "off";
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

	printf("Node appended: %s\n", new_node->sessionId);
}

// IDでノードを削除（成功で1、失敗で0）
int delete_node(const char sessionId[ID_SIZE]) {
	session_info_t *curr = head;
	session_info_t *prev = NULL;

	while (curr) {
		if (memcmp(curr->sessionId, sessionId, ID_SIZE) == 0) {
			printf("Node deleted: %s\n", curr->sessionId);
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
const char response_405[] = "HTTP/1.1 405 Method Not Allowed"HTTP_NEWLINE
	"Content-Length: 0"HTTP_NEWLINE
	"Allow: GET"HTTP_NEWLINE HTTP_NEWLINE;

#include "pico_fsdata.inc"

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
				printf("Response sent to SSE client: %x\n%s", (int)strlen(info->response), info->response);
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
	ip_addr_t ipaddr;
	ipaddr_aton(TO_STRING(WG_ADDRESS), &ipaddr);
	tcp_bind(pcb, &ipaddr, HTTP_PORT);
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
const char switch_busy[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32002, \"message\": \"Busy\"}, \"id\": %d}";
const char unknown_tool[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32602,\"message\":\"Unknown tool\"}}";
const char invalid_protocol[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32602,\"message\":\"Invalid protocol version\"}}";
const char invalid_context[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Invalid context\"}, \"id\": %d}";
const char missing_fields[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing fields\"}, \"id\": %d}";
const char missing_call_arguments[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Missing call arguments\"}, \"id\": %d}";
const char parse_error[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"error\":{\"code\":-32700,\"message\":\"Parse error\"}}";

const char resource[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"protocolVersion\":\"2025-03-26\",\"capabilities\":{\"logging\":{},\"tools\":{\"listChanged\":true}},\"serverInfo\":{\"name\":\"Raspberry Pi Pico Smart Home\",\"description\":\"A smart home system based on Raspberry Pi Pico.\",\"version\":\"1.0.0.0\"}}}";
const char tool_list[] = "{\"jsonrpc\":\"2.0\",\"id\":%d,\"result\":{\"tools\":["
		"{\"name\":\"set_switch\",\"description\":\"Trigger a momentary ATX power switch pulse (state is accepted but ignored).\",\"inputSchema\":{\"title\":\"set_switch\",\"description\":\"Trigger a momentary ATX power switch pulse (state is accepted but ignored).\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"},\"state\":{\"type\":\"string\",\"enum\":[\"on\",\"off\"]}},\"required\":[\"state\"]}},"
		"{\"name\":\"set_location\",\"description\":\"Set the location of the switch.\",\"inputSchema\":{\"title\":\"set_location\",\"description\":\"Set the location of the switch.\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"}},\"required\":[\"location\"]}},"
		"{\"name\":\"set_switch_id\",\"description\":\"Set the ID of the switch.\",\"inputSchema\":{\"title\":\"set_switch_id\",\"description\":\"Set the ID of the switch.\",\"type\":\"object\",\"properties\":{\"switch_id\":{\"type\":\"string\"},\"location\":{\"type\":\"string\"}},\"required\":[\"switch_id\"]}},"
		"{\"name\":\"send_key\",\"description\":\"Send a USB HID key press.\",\"inputSchema\":{\"type\":\"object\",\"properties\":{\"key\":{\"type\":\"string\"},\"combo\":{\"type\":\"array\",\"items\":{\"type\":\"string\"}}}}},"
		"{\"name\":\"wol_send\",\"description\":\"Send a Wake-on-LAN magic packet.\",\"inputSchema\":{\"title\":\"wol_send\",\"type\":\"object\",\"properties\":{\"mac\":{\"type\":\"string\"},\"port\":{\"type\":\"number\",\"enum\":[7,9],\"default\":9},\"broadcast_ip\":{\"type\":\"string\"}},\"required\":[\"mac\"]}},"
		"{\"name\":\"arp_probe\",\"description\":\"Probe ARP for an IPv4 address.\",\"inputSchema\":{\"title\":\"arp_probe\",\"type\":\"object\",\"properties\":{\"ip\":{\"type\":\"string\"},\"timeout_ms\":{\"type\":\"number\",\"default\":1000}},\"required\":[\"ip\"]}},"
		"{\"name\":\"wol_send_and_probe\",\"description\":\"Send WoL then ARP probe.\",\"inputSchema\":{\"title\":\"wol_send_and_probe\",\"type\":\"object\",\"properties\":{\"mac\":{\"type\":\"string\"},\"ip\":{\"type\":\"string\"},\"port\":{\"type\":\"number\",\"enum\":[7,9],\"default\":9},\"broadcast_ip\":{\"type\":\"string\"},\"timeout_ms\":{\"type\":\"number\",\"default\":1000}},\"required\":[\"mac\",\"ip\"]}}}"
	"]}}";
const char call_result[] = "{\"jsonrpc\": \"2.0\", \"result\": {\"status\": \"success\", \"content\": [%s]}, \"id\": %d}\n";
const char invalid_params[] = "{\"jsonrpc\": \"2.0\", \"error\": {\"code\": -32602, \"message\": \"Invalid params\"}, \"id\": %d}";

// コンテキスト保持（簡易構造体）
typedef struct
{
	char location[128];
	char switch_id[32];
} SwitchServerContext;

SwitchServerContext context;

void handle_set_location(session_info_t *info, JSON_Object *arguments, int id)
{
	const char *location = json_object_get_string(arguments, "location");

	if (location) {
		strncpy(context.location, location, sizeof(context.location));
		char content[256];
		sprintf(content, "{\"switch_id\":\"%s\",\"location\":\"%s\",\"state\":\"%s\"}",
			context.switch_id, context.location, get_switch_state());
		response_printf(info, call_result, content, id);
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
		char content[256];
		sprintf(content, "{\"switch_id\":\"%s\",\"location\":\"%s\",\"state\":\"%s\"}",
			context.switch_id, context.location, get_switch_state());
		response_printf(info, call_result, content, id);
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
		(void)state;
		if (!atx_power_pulse(ATX_PWR_PULSE_MS)) {
			response_printf(info, switch_busy, id);
			return;
		}
		char content[256];
		sprintf(content, "{\"switch_id\":\"%s\",\"location\":\"%s\",\"result\":\"pulse triggered\"}",
			context.switch_id, context.location);
		response_printf(info, call_result, content, id);
	}
	else {
		response_printf(info, location_not_configured, id);
	}
}

void handle_wol_send(session_info_t *info, JSON_Object *arguments, int id)
{
	if (!arguments) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	const char *mac = json_object_get_string(arguments, "mac");
	const char *broadcast_ip = json_object_get_string(arguments, "broadcast_ip");
	uint16_t port = 9;
	char err[64] = { 0 };

	if (!mac) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	if (!wol_get_port_from_json(arguments, &port, err, sizeof(err))) {
		char content[128];
		snprintf(content, sizeof(content), "{\"ok\":false,\"error\":\"%s\"}", err);
		response_printf(info, call_result, content, id);
		return;
	}

	if (wol_send_core(mac, broadcast_ip, port, err, sizeof(err))) {
		response_printf(info, call_result, "{\"ok\":true}", id);
	} else {
		char content[128];
		snprintf(content, sizeof(content), "{\"ok\":false,\"error\":\"%s\"}", err[0] ? err : "failed");
		response_printf(info, call_result, content, id);
	}
}

void handle_arp_probe(session_info_t *info, JSON_Object *arguments, int id)
{
	if (!arguments) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	const char *ip = json_object_get_string(arguments, "ip");
	uint32_t timeout_ms = wol_get_timeout_from_json(arguments);
	char err[64] = { 0 };
	const char *reason = NULL;
	bool arp_ok = false;

	if (!ip) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	if (wol_arp_probe_core(ip, timeout_ms, &arp_ok, &reason, err, sizeof(err))) {
		char content[160];
		if (arp_ok) {
			snprintf(content, sizeof(content), "{\"checked\":true,\"arp_ok\":true}");
		} else {
			snprintf(content, sizeof(content), "{\"checked\":true,\"arp_ok\":false,\"reason\":\"%s\"}", reason ? reason : "timeout");
		}
		response_printf(info, call_result, content, id);
	} else {
		char content[160];
		snprintf(content, sizeof(content), "{\"checked\":false,\"arp_ok\":false,\"error\":\"%s\"}", err[0] ? err : "failed");
		response_printf(info, call_result, content, id);
	}
}

void handle_wol_send_and_probe(session_info_t *info, JSON_Object *arguments, int id)
{
	if (!arguments) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	const char *mac = json_object_get_string(arguments, "mac");
	const char *ip = json_object_get_string(arguments, "ip");
	const char *broadcast_ip = json_object_get_string(arguments, "broadcast_ip");
	uint16_t port = 9;
	uint32_t timeout_ms = wol_get_timeout_from_json(arguments);
	char err[64] = { 0 };

	if (!mac || !ip) {
		response_printf(info, missing_call_arguments, id);
		return;
	}

	if (!wol_get_port_from_json(arguments, &port, err, sizeof(err))) {
		char content[128];
		snprintf(content, sizeof(content), "{\"wol_sent\":false,\"error\":\"%s\"}", err);
		response_printf(info, call_result, content, id);
		return;
	}

	const char *reason = NULL;
	bool arp_ok = false;
	if (wol_send_and_probe_core(mac, ip, broadcast_ip, port, timeout_ms, &arp_ok, &reason, err, sizeof(err))) {
		char content[180];
		if (arp_ok) {
			snprintf(content, sizeof(content), "{\"wol_sent\":true,\"arp_checked\":true,\"arp_ok\":true}");
		} else {
			snprintf(content, sizeof(content), "{\"wol_sent\":true,\"arp_checked\":true,\"arp_ok\":false,\"reason\":\"%s\"}", reason ? reason : "timeout");
		}
		response_printf(info, call_result, content, id);
	} else {
		char content[160];
		snprintf(content, sizeof(content), "{\"wol_sent\":false,\"error\":\"%s\"}", err[0] ? err : "failed");
		response_printf(info, call_result, content, id);
	}
}

// -------------------- USB HID keyboard support --------------------

enum hid_evt_type {
	HID_EVT_KEYBOARD,
	HID_EVT_CONSUMER,
	HID_EVT_SYSTEM
};

typedef struct {
	enum hid_evt_type type;
	uint8_t modifier;
	uint8_t keycode;
	uint16_t usage;
	uint8_t system_code;
} hid_tap_evt_t;

static queue_t g_hid_q;

// Tap a single HID key (press then release).
static void hid_tap_keyboard(uint8_t modifier, uint8_t keycode)
{
	hid_tap_evt_t e = {
		.type = HID_EVT_KEYBOARD,
		.modifier = modifier,
		.keycode = keycode,
		.usage = 0,
		.system_code = 0
	};

	// 連打取り逃がしOK → 失敗したら捨てる
	(void)queue_try_add(&g_hid_q, &e);
}

static void hid_tap_consumer(uint16_t usage)
{
	hid_tap_evt_t e = {
		.type = HID_EVT_CONSUMER,
		.modifier = 0,
		.keycode = 0,
		.usage = usage,
		.system_code = 0
	};
	(void)queue_try_add(&g_hid_q, &e);
}

static void hid_tap_system(uint8_t system_code)
{
	hid_tap_evt_t e = {
		.type = HID_EVT_SYSTEM,
		.modifier = 0,
		.keycode = 0,
		.usage = 0,
		.system_code = system_code
	};
	(void)queue_try_add(&g_hid_q, &e);
}

enum hid_state {
	HID_IDLE,
	HID_PRESSED,
	HID_RELEASED
};

static void core1_usb_main(void)
{
	enum hid_state state = HID_IDLE;
	absolute_time_t now, timeout;
	hid_tap_evt_t active = {0};

	board_init();
	tusb_init();

	while (true) {
		// TinyUSB device task (HID)
		tud_task();

		if (!tud_hid_ready()) continue;
		now = get_absolute_time();

		switch (state) {
		case HID_IDLE:
			if (!queue_try_remove(&g_hid_q, &active)) 
				break;
			// press
			if (active.type == HID_EVT_KEYBOARD) {
				uint8_t keycodes[6] = { active.keycode, 0,0,0,0,0 };
				tud_hid_keyboard_report(REPORT_ID_KEYBOARD, active.modifier, keycodes);
			} else if (active.type == HID_EVT_CONSUMER) {
				uint16_t usage = active.usage;
				tud_hid_report(REPORT_ID_CONSUMER_CONTROL, &usage, sizeof(usage));
			} else if (active.type == HID_EVT_SYSTEM) {
				uint8_t system_code = active.system_code;
				tud_hid_report(REPORT_ID_SYSTEM_CONTROL, &system_code, sizeof(system_code));
			}
			timeout = delayed_by_ms(now, 5); // 5ms後
			state = HID_PRESSED;
			break;
		case HID_PRESSED:
			if (absolute_time_diff_us(now, timeout) > 0)
				break; // まだタイムアウトしていない
			if (active.type == HID_EVT_KEYBOARD) {
				uint8_t empty[6] = { 0 };
				tud_hid_keyboard_report(REPORT_ID_KEYBOARD, 0, empty);
			} else if (active.type == HID_EVT_CONSUMER) {
				uint16_t usage = 0;
				tud_hid_report(REPORT_ID_CONSUMER_CONTROL, &usage, sizeof(usage));
			} else if (active.type == HID_EVT_SYSTEM) {
				uint8_t system_code = 0;
				tud_hid_report(REPORT_ID_SYSTEM_CONTROL, &system_code, sizeof(system_code));
			}
			timeout = delayed_by_ms(now, 5); // 5ms後
			state = HID_RELEASED;
			break;
		case HID_RELEASED:
			if (absolute_time_diff_us(now, timeout) > 0)
				break; // まだタイムアウトしていない
			state = HID_IDLE;
			break;
		}
		tight_loop_contents();
	}
}

// Minimal key mapping: a-z, A-Z, digits, and some named keys.
static bool map_key_string(const char *key, uint8_t *modifier, uint8_t *keycode)
{
	*modifier = 0;
	*keycode = 0;

	if (!key || key[0] == '\0') return false;

	// Single character
	if (key[1] == '\0') {
		char c = key[0];
		if (c >= 'a' && c <= 'z') { *keycode = (uint8_t)(HID_KEY_A + (c - 'a')); return true; }
		if (c >= 'A' && c <= 'Z') { *modifier = KEYBOARD_MODIFIER_LEFTSHIFT; *keycode = (uint8_t)(HID_KEY_A + (c - 'A')); return true; }
		if (c >= '1' && c <= '9') { *keycode = (uint8_t)(HID_KEY_1 + (c - '1')); return true; }
		if (c == '0') { *keycode = HID_KEY_0; return true; }
		if (c == ' ') { *keycode = HID_KEY_SPACE; return true; }
	}

	// Named keys
	if (strcasecmp(key, "Enter") == 0) { *keycode = HID_KEY_ENTER; return true; }
	if (strcasecmp(key, "Backspace") == 0) { *keycode = HID_KEY_BACKSPACE; return true; }
	if (strcasecmp(key, "Escape") == 0 || strcasecmp(key, "Esc") == 0) { *keycode = HID_KEY_ESCAPE; return true; }
	if (strcasecmp(key, "Tab") == 0) { *keycode = HID_KEY_TAB; return true; }
	if (strcasecmp(key, "Space") == 0) { *keycode = HID_KEY_SPACE; return true; }

	return false;
}

static bool map_system_key_string(const char *key, uint8_t *system_code)
{
	if (strcasecmp(key, "Power") == 0) { *system_code = 1; return true; }
	if (strcasecmp(key, "Sleep") == 0) { *system_code = 2; return true; }
	return false;
}

static bool map_consumer_key_string(const char *key, uint16_t *usage)
{
	if (strcasecmp(key, "Mute") == 0 || strcasecmp(key, "VolumeMute") == 0) {
		*usage = HID_USAGE_CONSUMER_MUTE;
		return true;
	}
	return false;
}

static uint8_t modifier_from_name(const char *name)
{
	if (!name) return 0;
	if (strcasecmp(name, "CTRL") == 0 || strcasecmp(name, "CONTROL") == 0) return KEYBOARD_MODIFIER_LEFTCTRL;
	if (strcasecmp(name, "SHIFT") == 0) return KEYBOARD_MODIFIER_LEFTSHIFT;
	if (strcasecmp(name, "ALT") == 0) return KEYBOARD_MODIFIER_LEFTALT;
	if (strcasecmp(name, "GUI") == 0 || strcasecmp(name, "WIN") == 0 || strcasecmp(name, "CMD") == 0) return KEYBOARD_MODIFIER_LEFTGUI;
	return 0;
}

void handle_send_key(session_info_t *info, JSON_Object *arguments, int id)
{
	const char *key = json_object_get_string(arguments, "key");
	JSON_Array *combo = json_object_get_array(arguments, "combo");

	uint8_t mod = 0;
	uint8_t code = 0;

	if (combo && json_array_get_count(combo) >= 1) {
		// Interpret combo as ["CTRL","c"] etc.
		for (size_t i = 0; i < json_array_get_count(combo); i++) {
			const char *s = json_array_get_string(combo, i);
			uint8_t m = modifier_from_name(s);
			if (m) {
				mod |= m;
			} else if (!code) {
				// First non-modifier is treated as the main key
				if (!map_key_string(s, &mod, &code)) {
					// If mapping fails, try single-char lower/upper rule with current mod
					uint8_t tmp_mod = 0, tmp_code = 0;
					if (map_key_string(s, &tmp_mod, &tmp_code)) {
						mod |= tmp_mod;
						code = tmp_code;
					}
				}
			}
		}
	} else if (key) {
		uint8_t system_code = 0;
		uint16_t usage = 0;
		if (map_system_key_string(key, &system_code)) {
			hid_tap_system(system_code);
			response_printf(info, call_result, "\"{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"ok\\\"}\"", id);
			return;
		}
		if (map_consumer_key_string(key, &usage)) {
			hid_tap_consumer(usage);
			response_printf(info, call_result, "\"{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"ok\\\"}\"", id);
			return;
		}
		if (!map_key_string(key, &mod, &code)) {
			response_printf(info, invalid_params, id);
			return;
		}
	} else {
		response_printf(info, invalid_params, id);
		return;
	}

	if (!code) {
		response_printf(info, invalid_params, id);
		return;
	}

	hid_tap_keyboard(mod, code);

	// Return a minimal success payload
	response_printf(info, call_result, "\"{\\\"type\\\":\\\"text\\\",\\\"text\\\":\\\"ok\\\"}\"", id);
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
		tcp_write(info->pcb, file_404_html->data, file_404_html->len, TCP_WRITE_FLAG_COPY);
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

	if (strcmp(info->url, "/") == 0 || strcmp(info->url, "/kbd") == 0) {
		info->endpoint_type = ENDPOINT_KBD;
	}
	else if (strcmp(info->url, "/sse") == 0) {
		info->endpoint_type = ENDPOINT_SSE;
	}
	else if (strcmp(info->url, "/message") == 0) {
		info->endpoint_type = ENDPOINT_MESSAGE;
	}
	else if (strcmp(info->url, "/event") == 0) {
		info->endpoint_type = ENDPOINT_EVENT;
	}
	else if (strcmp(info->url, "/wol") == 0) {
		info->endpoint_type = ENDPOINT_WOL;
	}
	else if (strcmp(info->url, "/wol_allowlist.json") == 0) {
		info->endpoint_type = ENDPOINT_WOL_ALLOWLIST;
	}
	else if (strcmp(info->url, "/wol/send") == 0) {
		info->endpoint_type = ENDPOINT_WOL_SEND;
	}
	else if (strcmp(info->url, "/wol/probe") == 0) {
		info->endpoint_type = ENDPOINT_WOL_PROBE;
	}
	else if (strcmp(info->url, "/wol/send_and_probe") == 0) {
		info->endpoint_type = ENDPOINT_WOL_SEND_AND_PROBE;
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

	printf("HTTP request completed: %s %s\n%s\n", info->method, info->url, info->request ? info->request : "");

	switch (info->endpoint_type) {
	case ENDPOINT_SSE:
		if (strcmp(info->method, "POST") == 0) {
			tcp_write(info->pcb, response_405, strlen(response_405), TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
			printf("POST method not allowed for /sse endpoint\n");
		}
		else {
			generate_guid(info->sessionId);
			info->sse_pcb = info->pcb; // SSE用のPCBを保存
			append_node(info);
			char rpc[127] = { 0 };
			int len = snprintf(rpc, sizeof(rpc), "event: endpoint"SSE_NEWLINE"data: /message?sessionId=%s"SSE_NEWLINE SSE_SEPARATOR, info->sessionId);
			char response[512] = { 0 };
			len = snprintf(response, sizeof(response), "%s%x"HTTP_NEWLINE"%s"HTTP_NEWLINE, response_200, (int)strlen(rpc), rpc);
			tcp_write(info->pcb, response, strlen(response), TCP_WRITE_FLAG_COPY);
			printf("SSE session started: %s\n", info->sessionId);
		}
		break;

	case ENDPOINT_KBD:
		if (strcmp(info->method, "GET") != 0) {
			tcp_write(info->pcb, response_405, strlen(response_405), TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
			printf("Non-GET method not allowed for keyboard page\n");
		} else {
			tcp_write(info->pcb, file_keyboard_html->data, file_keyboard_html->len, TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
		}
		break;
	case ENDPOINT_WOL:
		if (strcmp(info->method, "GET") != 0) {
			tcp_write(info->pcb, response_405, strlen(response_405), TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
			printf("Non-GET method not allowed for wol page\n");
		} else {
			tcp_write(info->pcb, file_wol_html->data, file_wol_html->len, TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
		}
		return 0;
	case ENDPOINT_WOL_ALLOWLIST:
		if (strcmp(info->method, "GET") != 0) {
			tcp_write(info->pcb, response_405, strlen(response_405), TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
			printf("Non-GET method not allowed for wol allowlist\n");
		} else {
			tcp_write(info->pcb, file_wol_allowlist_json->data, file_wol_allowlist_json->len, TCP_WRITE_FLAG_COPY);
			free(info->request);
			info->request = NULL;
		}
		return 0;
	case ENDPOINT_WOL_SEND:
		wol_http_send(info);
		return 0;
	case ENDPOINT_WOL_PROBE:
		wol_http_probe(info);
		return 0;
	case ENDPOINT_WOL_SEND_AND_PROBE:
		wol_http_send_and_probe(info);
		return 0;

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
			printf("Message received for session: %s\n", sse->sessionId);
		}
		else {
			tcp_write(info->pcb, response_400, strlen(response_400), TCP_WRITE_FLAG_COPY);
			printf("Session not found for message of session: %s\n", sse->sessionId);
		}
		break;
	case ENDPOINT_NOT_FOUND:
		tcp_write(info->pcb, file_404_html->data, file_404_html->len, TCP_WRITE_FLAG_COPY);
		free(info->request);
		info->request = NULL;
		printf("Endpoint not found: %s\n", info->url);
		return 0;
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
		else if (strcmp(name, "send_key") == 0) {
			handle_send_key(info, arguments, id);
		}
		else if (strcmp(name, "wol_send") == 0) {
			handle_wol_send(info, arguments, id);
		}
		else if (strcmp(name, "arp_probe") == 0) {
			handle_arp_probe(info, arguments, id);
		}
		else if (strcmp(name, "wol_send_and_probe") == 0) {
			handle_wol_send_and_probe(info, arguments, id);
		}
	}
	else {
		response_printf(info, method_not_found, id);
	}

	json_value_free(val);

	return 0;
}

void connect_wireguard() {
	struct wireguardif_init_data wg;
	struct wireguardif_peer peer;
	ip_addr_t ipaddr;
	ipaddr_aton(TO_STRING(WG_ADDRESS), &ipaddr);
	ip_addr_t netmask;
	ipaddr_aton(TO_STRING(WG_SUBNET_MASK_IP), &netmask);
	ip_addr_t gateway;
	ipaddr_aton(TO_STRING(WG_GATEWAY_IP), &gateway);

	wg.private_key = TO_STRING(WG_PRIVATE_KEY);
	wg.listen_port = 51820;
	wg.bind_netif = NULL;

	wg_netif = netif_add(&wg_netif_struct, &ipaddr, &netmask, &gateway, &wg,
						&wireguardif_init, &ip_input);

	netif_set_up(wg_netif);

	wireguardif_peer_init(&peer);
	peer.public_key = TO_STRING(WG_PUBLIC_KEY);
	peer.preshared_key = NULL;
	peer.keep_alive = WG_KEEPALIVE;
	ipaddr_aton(TO_STRING(WG_ALLOWED_IP), &peer.allowed_ip);
	ipaddr_aton(TO_STRING(WG_ALLOWED_IP_MASK_IP), &peer.allowed_mask);
	ipaddr_aton(TO_STRING(WG_ENDPOINT_IP), &peer.endpoint_ip);
	peer.endport_port = WG_ENDPOINT_PORT;

	wireguardif_add_peer(wg_netif, &peer, &wireguard_peer_index);

	if ((wireguard_peer_index != WIREGUARDIF_INVALID_INDEX) &&
		!ip_addr_isany(&peer.endpoint_ip)) {
		wireguardif_connect(wg_netif, wireguard_peer_index);
	}
}

/* Network */
extern uint8_t mac[6];
static ip_addr_t g_ip;
static ip_addr_t g_mask;
static ip_addr_t g_gateway;
static ip_addr_t g_dnsserver;

int loop()
{
	uint8_t *pack = malloc(ETHERNET_MTU);
	uint16_t pack_len = 0;
	struct pbuf *p = NULL;
	
	http_server_init();
	printf("HTTP server initialized.\n");

	while (true) {
		getsockopt(SOCKET_MACRAW, SO_RECVBUF, &pack_len);

		if (pack_len > 0)
		{
			pack_len = recv_lwip(SOCKET_MACRAW, (uint8_t *)pack, pack_len);

			if (pack_len)
			{
				p = pbuf_alloc(PBUF_RAW, pack_len, PBUF_POOL);
				pbuf_take(p, pack, pack_len);
				free(pack);

				pack = malloc(ETHERNET_MTU);
			}
			else
			{
				printf(" No packet received\n");
			}

			if (pack_len && p != NULL)
			{
				LINK_STATS_INC(link.recv);

				if (g_netif.input(p, &g_netif) != ERR_OK)
				{
					pbuf_free(p);
				}
			}
		}

		/* Cyclic lwIP timers check */
		sys_check_timeouts();

		sleep_ms(1);
	}
}

/* Clock */
static void set_clock_khz(void)
{
	// set a system clock frequency in khz
	set_sys_clock_khz(PLL_SYS_KHZ, true);

	// configure the specified clock
	clock_configure(
		clk_peri,
		0,                                                // No glitchless mux
		CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLKSRC_PLL_SYS, // System PLL on AUX mux
		PLL_SYS_KHZ * 1000,                               // Input frequency
		PLL_SYS_KHZ * 1000                                // Output (must be same as no divider)
	);
}

int main()
{
	int8_t retval = 0;

	set_clock_khz();

	critical_section_init(&g_pwr_pulse_cs);

	gpio_init(ATX_PWR_GPIO);
	gpio_set_dir(ATX_PWR_GPIO, GPIO_OUT);
	gpio_put(ATX_PWR_GPIO, ATX_PWR_ACTIVE_LEVEL ? 0 : 1);
	// NOTE: Use a transistor/photocoupler for isolation when wiring to ATX PWR_SW.

	gpio_init(PWR_LED_GPIO);
	gpio_set_dir(PWR_LED_GPIO, GPIO_IN);
	if (PWR_LED_PULL == 1) {
		gpio_pull_down(PWR_LED_GPIO);
	} else if (PWR_LED_PULL == 2) {
		gpio_pull_up(PWR_LED_GPIO);
	} else {
		gpio_disable_pulls(PWR_LED_GPIO);
	}

	stdio_init_all();

	queue_init(&g_hid_q, sizeof(hid_tap_evt_t), 32); // 連打は捨ててOKなら浅くて良い

	multicore_launch_core1(core1_usb_main);

	//while(!stdio_usb_connected())
	//	__asm("WFI");
	sleep_ms(1000 * 3); // wait for 3 seconds

	wizchip_spi_initialize();
	wizchip_cris_initialize();

	wizchip_reset();
	wizchip_initialize();
	wizchip_check();

	// Set ethernet chip MAC address
	setSHAR(mac);
	ctlwizchip(CW_RESET_PHY, 0);

	// Initialize LWIP in NO_SYS mode
	lwip_init();

	if (enable_dhcp) {
		// When configuring a static IP address on a DHCP server (wg0.conf endpoint ip address)
		printf(" DHCP client enable\n");
		netif_add(&g_netif, IP4_ADDR_ANY, IP4_ADDR_ANY, IP4_ADDR_ANY, NULL, netif_initialize, netif_input);
	}
	else {
		// Static IP address initialization (wg0.conf endpoint ip address)
		printf(" Static IP address configure\n");
		ipaddr_aton(TO_STRING(ENDPOINT_IP), &g_ip);
		ipaddr_aton(TO_STRING(ENDPOINT_SUBNET_MASK_IP), &g_mask);
		ipaddr_aton(TO_STRING(ENDPOINT_GATEWAY_IP), &g_gateway);
		netif_add(&g_netif, &g_ip, &g_mask, &g_gateway, NULL, netif_initialize, netif_input);
	}

	// Set interface name
	g_netif.name[0] = 'e';
	g_netif.name[1] = '0';

	// Assign callbacks for link and status
	netif_set_link_callback(&g_netif, netif_link_callback);
	netif_set_status_callback(&g_netif, netif_status_callback);

	// MACRAW socket open
	retval = socket(SOCKET_MACRAW, Sn_MR_MACRAW, PORT_LWIPERF, 0x00);

	if (retval < 0)
	{
		printf(" MACRAW socket open failed\n");
	}

	// Set the default interface and bring it up
	netif_set_default(&g_netif);
	netif_set_link_up(&g_netif);
	netif_set_up(&g_netif);

	if (enable_dhcp) {
		printf("Start DHCP configuration for an interface\n");
		dhcp_start(&g_netif);
	}

	ipaddr_aton(TO_STRING(DNS_SERVER_IP), &g_dnsserver);
	if (g_dnsserver.addr != 0) {
		dns_setserver(0, &g_dnsserver);
		dns_init();
	}

	connect_wireguard();

	while (true) {
		loop();
	}
}

