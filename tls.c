// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * TLS/SSL support for xfrpc using mbedTLS + libevent (>= 2.2).
 *
 * libevent 2.2 provides bufferevent_mbedtls_* as the mbedTLS counterpart
 * of bufferevent_openssl_*.  A heap-allocated mbedtls_ssl_context
 * (mbedtls_dyncontext) is created per connection from the shared global
 * mbedtls_ssl_config; the bufferevent owns it once attached.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <mbedtls/error.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

#include <event2/bufferevent_ssl.h>

#include "ssl_compat.h"
#include "tls.h"
#include "config.h"
#include "debug.h"

/* 全局共享 TLS 配置（mbedtls_ssl_config 可在多连接间只读共享） */
static mbedtls_ssl_config g_ssl_conf;
static mbedtls_x509_crt   g_ca_crt;    /* 信任的 CA 证书链 */
static mbedtls_x509_crt   g_cli_crt;   /* 客户端证书（mTLS，可选） */
static mbedtls_pk_context g_cli_key;   /* 客户端私钥（mTLS，可选） */
static int g_conf_inited = 0;

/**
 * 记录 mbedTLS 错误码到调试日志。
 */
static void tls_log_error(const char *context, int err)
{
	if (err >= 0) return;
	char buf[160];
	mbedtls_strerror(err, buf, sizeof(buf));
	debug(LOG_ERR, "[TLS] %s: -0x%04X (%s)", context, (unsigned)-err, buf);
}

/**
 * 记录 bufferevent_mbedtls 上保存的最近一次 TLS 错误。
 * mbedTLS 没有 OpenSSL 那样的线程级错误队列，libevent 将 mbedtls
 * 负错误码保存在 bufferevent 内部，通过 bufferevent_get_mbedtls_error()
 * 取出（返回 unsigned long，需转回 int 得到原始负错误码）。
 */
void tls_log_bev_error(struct bufferevent *bev, const char *context)
{
	if (!bev) return;
	unsigned long err = bufferevent_get_mbedtls_error(bev);
	if (err == 0) return;
	tls_log_error(context ? context : "connection", (int)err);
}

/**
 * Check if TLS is enabled in the current configuration.
 */
int tls_is_enabled(void)
{
	struct common_conf *conf = get_common_config();
	return (conf && conf->tls_enable);
}

/**
 * mbedTLS 没有内建的系统 CA 信任库（OpenSSL 有
 * SSL_CTX_set_default_verify_paths）。这里探测常见 Linux/OpenWrt
 * 发行版的 CA bundle 路径并加载第一个可用文件。
 *
 * @return 0 成功加载，-1 未找到或加载失败
 */
static int tls_load_system_ca(mbedtls_x509_crt *ca)
{
	static const char * const paths[] = {
		"/etc/ssl/certs/ca-certificates.crt", /* Debian/Ubuntu/OpenWrt(ca-certificates) */
		"/etc/pki/tls/certs/ca-bundle.crt",   /* RHEL/CentOS/Fedora */
		"/etc/ssl/ca-bundle.pem",             /* SUSE */
		"/etc/ssl/cert.pem",                  /* Alpine */
		NULL,
	};

	for (int i = 0; paths[i]; i++) {
		if (access(paths[i], R_OK) != 0)
			continue;
		int ret = mbedtls_x509_crt_parse_file(ca, paths[i]);
		if (ret < 0) {
			tls_log_error("mbedtls_x509_crt_parse_file(system CA)", ret);
			return -1;
		}
		debug(LOG_DEBUG, "[TLS] Loaded system CA bundle: %s", paths[i]);
		return 0;
	}

	return -1;
}

/**
 * 证书校验回调：仅记录失败详情，是否拒绝握手由 authmode
 * （VERIFY_REQUIRED）与 *flags 决定。
 */
static int tls_verify_callback(void *data, mbedtls_x509_crt *crt,
                               int depth, uint32_t *flags)
{
	(void)data;
	(void)crt;

	if (*flags) {
		char info[256];
		mbedtls_x509_crt_verify_info(info, sizeof(info), "  ! ", *flags);
		debug(LOG_ERR, "[TLS] Certificate verification failed at depth %d:\n%s",
		      depth, info);
	}
	return 0;
}

/**
 * Initialize the global TLS configuration from common_conf settings.
 *
 * @return 0 on success, -1 on failure
 */
int tls_init(void)
{
	struct common_conf *conf = get_common_config();
	if (!conf || !conf->tls_enable) {
		debug(LOG_DEBUG, "[TLS] TLS is disabled");
		return 0;
	}

	if (g_conf_inited)
		return 0; /* 幂等 */

	mbedtls_ssl_config_init(&g_ssl_conf);
	mbedtls_x509_crt_init(&g_ca_crt);
	mbedtls_x509_crt_init(&g_cli_crt);
	mbedtls_pk_init(&g_cli_key);

	int ret = mbedtls_ssl_config_defaults(&g_ssl_conf,
	                                      MBEDTLS_SSL_IS_CLIENT,
	                                      MBEDTLS_SSL_TRANSPORT_STREAM,
	                                      MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		tls_log_error("mbedtls_ssl_config_defaults", ret);
		goto fail;
	}

	/* RNG（全局 CTR_DRBG，实现在 utils.c） */
	mbedtls_ssl_conf_rng(&g_ssl_conf, xfrpc_random, NULL);
	/* 最低 TLS 1.2（mbedTLS 默认即启用 TLS 1.2/1.3） */
	mbedtls_ssl_conf_min_tls_version(&g_ssl_conf, MBEDTLS_SSL_VERSION_TLS1_2);
	/* 证书校验结果回调（记录失败原因） */
	mbedtls_ssl_conf_verify(&g_ssl_conf, tls_verify_callback, NULL);

	/* ---- 受信 CA ---- */
	int has_ca = 0;
	if (conf->tls_trusted_ca_file) {
		ret = mbedtls_x509_crt_parse_file(&g_ca_crt, conf->tls_trusted_ca_file);
		if (ret < 0) {
			debug(LOG_ERR, "[TLS] Failed to load CA file: %s",
			      conf->tls_trusted_ca_file);
			tls_log_error("mbedtls_x509_crt_parse_file", ret);
			goto fail;
		}
		has_ca = 1;
		debug(LOG_DEBUG, "[TLS] CA file loaded: %s", conf->tls_trusted_ca_file);
	} else if (tls_load_system_ca(&g_ca_crt) == 0) {
		has_ca = 1;
	}

	if (has_ca) {
		mbedtls_ssl_conf_ca_chain(&g_ssl_conf, &g_ca_crt, NULL);
		mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	} else {
		/* 与 OpenSSL 行为不同：mbedTLS 无系统信任库自动加载机制；
		 * 找不到任何 CA 时只能关闭校验，明确告警提示风险。 */
		mbedtls_ssl_conf_authmode(&g_ssl_conf, MBEDTLS_SSL_VERIFY_NONE);
		debug(LOG_WARNING,
		      "[TLS] No CA bundle found (configure tls_trusted_ca_file or "
		      "install ca-certificates); certificate verification DISABLED");
	}

	/* ---- 客户端证书 + 私钥（mTLS，可选） ---- */
	if (conf->tls_cert_file) {
		ret = mbedtls_x509_crt_parse_file(&g_cli_crt, conf->tls_cert_file);
		if (ret < 0) {
			debug(LOG_ERR, "[TLS] Failed to load client cert: %s",
			      conf->tls_cert_file);
			tls_log_error("mbedtls_x509_crt_parse_file(cert)", ret);
			goto fail;
		}
		debug(LOG_DEBUG, "[TLS] Client certificate loaded: %s",
		      conf->tls_cert_file);

		if (conf->tls_key_file) {
			/* 3.6.x 原型：parse_keyfile(ctx, path, password(NUL 结尾),
			 * f_rng, p_rng)；password 为 NULL 表示无密码，无 pwdlen 参数 */
			ret = mbedtls_pk_parse_keyfile(&g_cli_key,
			                               conf->tls_key_file,
			                               NULL,
			                               xfrpc_random, NULL);
			if (ret != 0) {
				debug(LOG_ERR, "[TLS] Failed to load private key: %s",
				      conf->tls_key_file);
				tls_log_error("mbedtls_pk_parse_keyfile", ret);
				goto fail;
			}

			/* 校验私钥与证书匹配（3.6.x 需传入 f_rng/p_rng） */
			ret = mbedtls_pk_check_pair(&g_cli_crt.pk, &g_cli_key,
			                            xfrpc_random, NULL);
			if (ret != 0) {
				debug(LOG_ERR, "[TLS] Private key does not match certificate");
				tls_log_error("mbedtls_pk_check_pair", ret);
				goto fail;
			}

			mbedtls_ssl_conf_own_cert(&g_ssl_conf, &g_cli_crt, &g_cli_key);
			debug(LOG_DEBUG, "[TLS] Private key loaded: %s", conf->tls_key_file);
		} else {
			debug(LOG_WARNING,
			      "[TLS] Client certificate configured but no key file; ignored");
		}
	}

	g_conf_inited = 1;
	debug(LOG_INFO, "[TLS] TLS context initialized (TLS 1.2+, mbedTLS)");
	return 0;

fail:
	mbedtls_ssl_config_free(&g_ssl_conf);
	mbedtls_x509_crt_free(&g_ca_crt);
	mbedtls_x509_crt_free(&g_cli_crt);
	mbedtls_pk_free(&g_cli_key);
	return -1;
}

/**
 * Wrap a raw TCP bufferevent with TLS.
 *
 * Creates a per-connection mbedtls_ssl_context (heap dyncontext attached
 * to the shared config), sets SNI/verification hostname, and wraps the
 * socket fd in a new bufferevent_mbedtls.  The original bev is consumed.
 *
 * @param base  Event base
 * @param bev   Raw TCP bufferevent (consumed)
 * @return      TLS-wrapped bufferevent, or NULL on error
 */
struct bufferevent *tls_wrap_bev(struct event_base *base, struct bufferevent *bev)
{
	if (!g_conf_inited) {
		debug(LOG_ERR, "[TLS] TLS config not initialized");
		return NULL;
	}

	if (!bev) {
		debug(LOG_ERR, "[TLS] NULL bufferevent to wrap");
		return NULL;
	}

	/* Get the raw fd before freeing the plain bev */
	evutil_socket_t fd = bufferevent_getfd(bev);
	if (fd < 0) {
		debug(LOG_ERR, "[TLS] Cannot get fd from bufferevent");
		return NULL;
	}

	/* Detach fd from the plain bev so it survives bev_free */
	debug(LOG_DEBUG, "[TLS] Wrapping fd %d with TLS", (int)fd);
	bufferevent_setfd(bev, -1);
	bufferevent_free(bev);

	/* 创建堆分配的 mbedtls_ssl_context（内部已 mbedtls_ssl_init +
	 * mbedtls_ssl_setup(ssl, &g_ssl_conf)）；成功挂到 bufferevent 后
	 * 由 bufferevent 负责释放，失败路径需手动 dyncontext_free。 */
	mbedtls_dyncontext *ssl = bufferevent_mbedtls_dyncontext_new(&g_ssl_conf);
	if (!ssl) {
		debug(LOG_ERR, "[TLS] bufferevent_mbedtls_dyncontext_new failed");
		evutil_closesocket(fd);
		return NULL;
	}

	/* 设置 SNI 与证书校验主机名（mbedtls_ssl_set_hostname 同时作用于二者）；
	 * 裸 IP 地址不设置（与原 OpenSSL 行为一致）。 */
	struct common_conf *conf = get_common_config();
	const char *sni_host = conf->tls_server_name ? conf->tls_server_name
	                                            : conf->server_addr;
	if (sni_host) {
		struct in_addr addr4;
		struct in6_addr addr6;
		int is_ip = (inet_pton(AF_INET, sni_host, &addr4) == 1 ||
		             inet_pton(AF_INET6, sni_host, &addr6) == 1);
		if (!is_ip) {
			int ret = mbedtls_ssl_set_hostname(ssl, sni_host);
			if (ret != 0) {
				tls_log_error("mbedtls_ssl_set_hostname", ret);
			} else {
				debug(LOG_DEBUG, "[TLS] SNI/verify hostname set to: %s", sni_host);
			}
		} else {
			debug(LOG_DEBUG, "[TLS] Skipping hostname verification for IP address: %s",
			      sni_host);
		}
	}

	/* Create TLS-wrapped bufferevent */
	int sock_err = 0;
	socklen_t err_len = sizeof(sock_err);
	getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len);
	debug(LOG_DEBUG, "tls_wrap_bev: fd=%d, sock_error=%d (%s)",
	      (int)fd, sock_err, strerror(sock_err));

	struct bufferevent *ssl_bev = bufferevent_mbedtls_socket_new(
		base, fd, ssl,
		BUFFEREVENT_SSL_CONNECTING,
		BEV_OPT_CLOSE_ON_FREE | BEV_OPT_DEFER_CALLBACKS
	);

	if (!ssl_bev) {
		debug(LOG_ERR, "[TLS] bufferevent_mbedtls_socket_new failed");
		bufferevent_mbedtls_dyncontext_free(ssl);
		evutil_closesocket(fd);
		return NULL;
	}

	/* Allow dirty shutdown to avoid log noise on reconnect */
	bufferevent_mbedtls_set_allow_dirty_shutdown(ssl_bev, 1);

	debug(LOG_INFO, "[TLS] Connection wrapped with TLS (mbedTLS)");
	return ssl_bev;
}

/**
 * Clean up the global TLS configuration.
 */
void tls_cleanup(void)
{
	if (g_conf_inited) {
		mbedtls_ssl_config_free(&g_ssl_conf);
		mbedtls_x509_crt_free(&g_ca_crt);
		mbedtls_x509_crt_free(&g_cli_crt);
		mbedtls_pk_free(&g_cli_key);
		g_conf_inited = 0;
		debug(LOG_DEBUG, "[TLS] TLS config freed");
	}
}

/**
 * Configure a standalone client TLS config (used by oidc_auth.c).
 * See tls.h for the policy description.
 */
int tls_configure_client_ssl(mbedtls_ssl_config *conf, mbedtls_x509_crt *ca,
                             const char *ca_file, int insecure)
{
	int ret;

	ret = mbedtls_ssl_config_defaults(conf,
	                                  MBEDTLS_SSL_IS_CLIENT,
	                                  MBEDTLS_SSL_TRANSPORT_STREAM,
	                                  MBEDTLS_SSL_PRESET_DEFAULT);
	if (ret != 0) {
		tls_log_error("mbedtls_ssl_config_defaults", ret);
		return ret;
	}

	mbedtls_ssl_conf_rng(conf, xfrpc_random, NULL);
	mbedtls_ssl_conf_min_tls_version(conf, MBEDTLS_SSL_VERSION_TLS1_2);
	mbedtls_ssl_conf_verify(conf, tls_verify_callback, NULL);

	if (insecure) {
		mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
		debug(LOG_WARNING, "[TLS] OIDC: certificate verification disabled (insecure)");
		return 0;
	}

	int has_ca = 0;
	if (ca_file) {
		ret = mbedtls_x509_crt_parse_file(ca, ca_file);
		if (ret < 0) {
			debug(LOG_ERR, "[TLS] OIDC: failed to load CA file: %s", ca_file);
			tls_log_error("mbedtls_x509_crt_parse_file", ret);
			return ret;
		}
		has_ca = 1;
		debug(LOG_DEBUG, "[TLS] OIDC: CA file loaded: %s", ca_file);
	} else if (tls_load_system_ca(ca) == 0) {
		has_ca = 1;
	}

	if (has_ca) {
		mbedtls_ssl_conf_ca_chain(conf, ca, NULL);
		mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_REQUIRED);
	} else {
		mbedtls_ssl_conf_authmode(conf, MBEDTLS_SSL_VERIFY_NONE);
		debug(LOG_WARNING,
		      "[TLS] OIDC: no CA bundle found; certificate verification DISABLED");
	}

	return 0;
}
