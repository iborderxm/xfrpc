// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2026 Dengfeng Liu <liudf0716@gmail.com>
 *
 * OIDC authentication for xfrpc.
 * Implements OAuth2 client_credentials grant to obtain access tokens.
 * Compatible with frp's auth.oidc.* configuration.
 *
 * Uses raw HTTP/HTTPS POST via mbedTLS + sockets (no external HTTP library).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <json-c/json.h>

#include "oidc_auth.h"
#include "tls.h"
#include "debug.h"

#define OIDC_RESPONSE_MAX 8192
#define OIDC_CONNECT_TIMEOUT 10

/* ---- URL parsing helper ---- */

struct parsed_url {
	char host[256];
	int port;
	char path[512];
	int is_https;
};

static int parse_url(const char *url, struct parsed_url *out)
{
	if (!url || !out) return -1;
	memset(out, 0, sizeof(*out));

	const char *p = url;
	if (strncmp(p, "https://", 8) == 0) {
		out->is_https = 1;
		out->port = 443;
		p += 8;
	} else if (strncmp(p, "http://", 7) == 0) {
		out->is_https = 0;
		out->port = 80;
		p += 7;
	} else {
		return -1;
	}

	/* Parse host:port/path */
	const char *slash = strchr(p, '/');
	const char *colon = strchr(p, ':');

	if (colon && (!slash || colon < slash)) {
		int host_len = colon - p;
		if (host_len >= (int)sizeof(out->host)) return -1;
		memcpy(out->host, p, host_len);
		out->host[host_len] = '\0';
		out->port = atoi(colon + 1);
	} else {
		int host_len = slash ? (int)(slash - p) : (int)strlen(p);
		if (host_len >= (int)sizeof(out->host)) return -1;
		memcpy(out->host, p, host_len);
		out->host[host_len] = '\0';
	}

	if (slash) {
		snprintf(out->path, sizeof(out->path), "%s", slash);
	} else {
		strcpy(out->path, "/");
	}

	return 0;
}

/* ---- TCP connection ---- */

static int tcp_connect(const char *host, int port)
{
	struct addrinfo hints = {0}, *res = NULL;
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	char port_str[8];
	snprintf(port_str, sizeof(port_str), "%d", port);

	if (getaddrinfo(host, port_str, &hints, &res) != 0 || !res) {
		debug(LOG_ERR, "OIDC: DNS lookup failed for %s", host);
		return -1;
	}

	int fd = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
	if (fd < 0) {
		freeaddrinfo(res);
		return -1;
	}

	/* Set connect timeout */
	struct timeval tv = {.tv_sec = OIDC_CONNECT_TIMEOUT, .tv_usec = 0};
	setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

	if (connect(fd, res->ai_addr, res->ai_addrlen) < 0) {
		debug(LOG_ERR, "OIDC: connect to %s:%d failed: %s", host, port, strerror(errno));
		close(fd);
		freeaddrinfo(res);
		return -1;
	}

	freeaddrinfo(res);
	return fd;
}

/* ---- Send all bytes ---- */

static int send_all(int fd, const void *buf, size_t len)
{
	const char *p = buf;
	while (len > 0) {
		ssize_t n = send(fd, p, len, 0);
		if (n <= 0) return -1;
		p += n;
		len -= n;
	}
	return 0;
}

/* ---- mbedTLS BIO 回调：通过阻塞式 socket fd 收发 ---- */

static int oidc_bio_send(void *ctx, const unsigned char *buf, size_t len)
{
	int fd = *(int *)ctx;
	ssize_t n;
	do {
		n = send(fd, buf, len, 0);
	} while (n < 0 && errno == EINTR);

	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_WRITE;
		return MBEDTLS_ERR_NET_SEND_FAILED;
	}
	return (int)n;
}

static int oidc_bio_recv(void *ctx, unsigned char *buf, size_t len)
{
	int fd = *(int *)ctx;
	ssize_t n;
	do {
		n = recv(fd, buf, len, 0);
	} while (n < 0 && errno == EINTR);

	if (n == 0)
		return MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY;
	if (n < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK)
			return MBEDTLS_ERR_SSL_WANT_READ;
		return MBEDTLS_ERR_NET_RECV_FAILED;
	}
	return (int)n;
}

/* ---- SSL send/recv helpers ---- */

static int ssl_send_all(mbedtls_ssl_context *ssl, const void *buf, size_t len)
{
	const unsigned char *p = buf;
	while (len > 0) {
		int n = mbedtls_ssl_write(ssl, p, len);
		if (n == MBEDTLS_ERR_SSL_WANT_READ ||
		    n == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		if (n <= 0) return -1;
		p += n;
		len -= (size_t)n;
	}
	return 0;
}

static int ssl_recv_all(mbedtls_ssl_context *ssl, char *buf, size_t buf_size, size_t *out_len)
{
	*out_len = 0;
	while (*out_len < buf_size - 1) {
		int n = mbedtls_ssl_read(ssl,
		                         (unsigned char *)buf + *out_len,
		                         buf_size - 1 - *out_len);
		if (n == MBEDTLS_ERR_SSL_WANT_READ ||
		    n == MBEDTLS_ERR_SSL_WANT_WRITE)
			continue;
		if (n == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY)
			break;
		if (n <= 0)
			break;
		*out_len += (size_t)n;
	}
	buf[*out_len] = '\0';
	return (*out_len > 0) ? 0 : -1;
}

/* ---- Build POST body ---- */

static char *build_post_body(const char *client_id, const char *client_secret,
                             const char *audience, const char *scope)
{
	/* URL-encode a simple string (only encode spaces and special chars) */
	#define URLENCODE_MAX 1024
	char enc_id[URLENCODE_MAX], enc_secret[URLENCODE_MAX];
	char enc_aud[URLENCODE_MAX], enc_scope[URLENCODE_MAX];

	/* Simple percent-encode for common characters */
	auto void urlencode(const char *src, char *dst, size_t dst_size) {
		const char *hex = "0123456789ABCDEF";
		size_t pos = 0;
		for (; *src && pos < dst_size - 4; src++) {
			unsigned char c = (unsigned char)*src;
			if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
			    (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.') {
				dst[pos++] = c;
			} else if (c == ' ') {
				dst[pos++] = '+';
			} else {
				dst[pos++] = '%';
				dst[pos++] = hex[c >> 4];
				dst[pos++] = hex[c & 0xF];
			}
		}
		dst[pos] = '\0';
	}

	urlencode(client_id, enc_id, sizeof(enc_id));
	urlencode(client_secret, enc_secret, sizeof(enc_secret));

	char *body = malloc(2048);
	if (!body) return NULL;

	int len = snprintf(body, 2048,
		"grant_type=client_credentials"
		"&client_id=%s"
		"&client_secret=%s",
		enc_id, enc_secret);

	if (audience && *audience) {
		urlencode(audience, enc_aud, sizeof(enc_aud));
		len += snprintf(body + len, 2048 - len, "&audience=%s", enc_aud);
	}
	if (scope && *scope) {
		urlencode(scope, enc_scope, sizeof(enc_scope));
		len += snprintf(body + len, 2048 - len, "&scope=%s", enc_scope);
	}

	return body;
}

/* ---- Extract access_token from JSON response ---- */

static char *extract_access_token(const char *response)
{
	/* Find the JSON body (after \r\n\r\n) */
	const char *body = strstr(response, "\r\n\r\n");
	if (!body) body = strstr(response, "\n\n");
	if (!body) return NULL;
	body += (body[1] == '\n') ? 2 : 4;

	struct json_object *root = json_tokener_parse(body);
	if (!root) {
		debug(LOG_ERR, "OIDC: failed to parse token response JSON");
		return NULL;
	}

	struct json_object *token_obj = NULL;
	if (!json_object_object_get_ex(root, "access_token", &token_obj)) {
		debug(LOG_ERR, "OIDC: no access_token in response");
		json_object_put(root);
		return NULL;
	}

	const char *token_str = json_object_get_string(token_obj);
	char *result = token_str ? strdup(token_str) : NULL;
	json_object_put(root);

	if (result) {
		debug(LOG_INFO, "OIDC: got access token (len=%zu)", strlen(result));
	} else {
		debug(LOG_ERR, "OIDC: failed to extract access token");
	}
	return result;
}

/* ---- Main: fetch OIDC token ---- */

char *oidc_fetch_token(const char *token_endpoint_url,
                       const char *client_id,
                       const char *client_secret,
                       const char *audience,
                       const char *scope,
                       const char *trusted_ca_file,
                       int insecure_skip_verify)
{
	if (!token_endpoint_url || !client_id || !client_secret) {
		debug(LOG_ERR, "OIDC: missing required parameters");
		return NULL;
	}

	struct parsed_url url;
	if (parse_url(token_endpoint_url, &url) < 0) {
		debug(LOG_ERR, "OIDC: invalid token endpoint URL: %s", token_endpoint_url);
		return NULL;
	}

	debug(LOG_INFO, "OIDC: fetching token from %s (TLS=%d)", url.host, url.is_https);

	/* Build HTTP request */
	char *post_body = build_post_body(client_id, client_secret, audience, scope);
	if (!post_body) return NULL;

	char request[4096];
	int req_len = snprintf(request, sizeof(request),
		"POST %s HTTP/1.1\r\n"
		"Host: %s\r\n"
		"Content-Type: application/x-www-form-urlencoded\r\n"
		"Content-Length: %zu\r\n"
		"Connection: close\r\n"
		"\r\n"
		"%s",
		url.path, url.host, strlen(post_body), post_body);
	free(post_body);

	/* Connect */
	int fd = tcp_connect(url.host, url.port);
	if (fd < 0) return NULL;

	/* TLS objects (only used when the endpoint is https) */
	mbedtls_ssl_context  ssl;
	mbedtls_ssl_config   ssl_conf;
	mbedtls_x509_crt     ca_crt;
	int use_tls = 0;
	int ret;

	if (url.is_https) {
		mbedtls_ssl_init(&ssl);
		mbedtls_ssl_config_init(&ssl_conf);
		mbedtls_x509_crt_init(&ca_crt);

		/* 配置 RNG/CA/鉴权策略（ca_file 为 NULL 时探测系统信任库） */
		ret = tls_configure_client_ssl(&ssl_conf, &ca_crt,
		                               trusted_ca_file, insecure_skip_verify);
		if (ret != 0) {
			debug(LOG_ERR, "OIDC: TLS config failed");
			goto tls_fail;
		}

		if (mbedtls_ssl_setup(&ssl, &ssl_conf) != 0) {
			debug(LOG_ERR, "OIDC: mbedtls_ssl_setup failed");
			goto tls_fail;
		}

		/* BIO 绑定到阻塞式 socket fd */
		mbedtls_ssl_set_bio(&ssl, &fd, oidc_bio_send, oidc_bio_recv, NULL);

		/* SNI 与证书主机名校验（url.host 在整个函数内有效） */
		if (mbedtls_ssl_set_hostname(&ssl, url.host) != 0) {
			debug(LOG_ERR, "OIDC: mbedtls_ssl_set_hostname failed");
			goto tls_fail;
		}

		/* 阻塞式握手（WANT_READ/WRITE 时重试） */
		int hs;
		while ((hs = mbedtls_ssl_handshake(&ssl)) != 0) {
			if (hs != MBEDTLS_ERR_SSL_WANT_READ &&
			    hs != MBEDTLS_ERR_SSL_WANT_WRITE) {
				char ebuf[128];
				mbedtls_strerror(hs, ebuf, sizeof(ebuf));
				debug(LOG_ERR, "OIDC: TLS handshake failed: -0x%04X (%s)",
				      (unsigned)-hs, ebuf);
				goto tls_fail;
			}
		}
		use_tls = 1;
		debug(LOG_INFO, "OIDC: TLS handshake OK");
	}

	/* Send request */
	if (use_tls) {
		ret = ssl_send_all(&ssl, request, (size_t)req_len);
	} else {
		ret = send_all(fd, request, req_len);
	}
	if (ret < 0) {
		debug(LOG_ERR, "OIDC: failed to send request");
		goto tls_fail;
	}

	/* Read response */
	char *response = malloc(OIDC_RESPONSE_MAX);
	if (!response) {
		goto tls_fail;
	}

	size_t resp_len = 0;
	if (use_tls) {
		ret = ssl_recv_all(&ssl, response, OIDC_RESPONSE_MAX, &resp_len);
	} else {
		/* Read until connection closes */
		while (resp_len < OIDC_RESPONSE_MAX - 1) {
			ssize_t n = recv(fd, response + resp_len,
			                 OIDC_RESPONSE_MAX - 1 - resp_len, 0);
			if (n <= 0) break;
			resp_len += n;
		}
		response[resp_len] = '\0';
		ret = (resp_len > 0) ? 0 : -1;
	}
	close(fd);

	/* 释放 mbedTLS 对象（ssl_setup 分配的内部资源随 ssl_free 释放） */
	if (use_tls) {
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&ssl_conf);
		mbedtls_x509_crt_free(&ca_crt);
	}

	if (ret < 0) {
		debug(LOG_ERR, "OIDC: failed to read response");
		free(response);
		return NULL;
	}

	/* Extract access_token */
	char *token = extract_access_token(response);
	free(response);
	return token;

tls_fail:
	/* 握手/发送阶段失败：释放 TLS 对象并关闭连接 */
	if (use_tls || url.is_https) {
		mbedtls_ssl_free(&ssl);
		mbedtls_ssl_config_free(&ssl_conf);
		mbedtls_x509_crt_free(&ca_crt);
	}
	close(fd);
	return NULL;
}
