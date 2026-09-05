// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * TLS transport for xfrpc, based on mbedTLS + libevent (>= 2.2)
 * bufferevent_mbedtls_*.
 */

#ifndef XFRPC_TLS_H
#define XFRPC_TLS_H

#include <event2/bufferevent.h>
#include <event2/bufferevent_ssl.h>

#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/pk.h>

/**
 * Initialize the global TLS configuration from common_conf.
 * Must be called once before any TLS connections are made.
 *
 * @return 0 on success, -1 on failure
 */
int tls_init(void);

/**
 * Wrap an existing TCP bufferevent with TLS.
 * The original bev is consumed; returns a new TLS-wrapped bev on success,
 * or NULL on failure (original bev is freed on failure).
 *
 * @param base   Event base for the new bufferevent
 * @param bev    The raw TCP bufferevent to wrap (consumed on success)
 * @return       TLS-wrapped bufferevent, or NULL on error
 */
struct bufferevent *tls_wrap_bev(struct event_base *base, struct bufferevent *bev);

/**
 * Clean up and free the global TLS configuration.
 * Call during shutdown.
 */
void tls_cleanup(void);

/**
 * Check if TLS is enabled in configuration.
 *
 * @return 1 if TLS is enabled, 0 otherwise
 */
int tls_is_enabled(void);

/**
 * Configure a client-side mbedtls_ssl_config for a standalone (blocking)
 * TLS connection. Used by oidc_auth.c.
 *
 * Sets up RNG, minimum TLS 1.2, the verify callback and certificate
 * verification policy:
 *   - insecure == 1: MBEDTLS_SSL_VERIFY_NONE
 *   - ca_file != NULL: that CA bundle is loaded and verification is required
 *   - otherwise the system CA bundle is probed; if none is found,
 *     verification is disabled with a warning (mbedTLS has no built-in
 *     system trust store, unlike OpenSSL)
 *
 * @param conf      Caller-initialized ssl_config (mbedtls_ssl_config_init)
 * @param ca        Caller-initialized x509_crt (mbedtls_x509_crt_init)
 * @param ca_file   Optional CA bundle PEM path (may be NULL)
 * @param insecure  1 to skip certificate verification
 * @return 0 on success, mbedTLS negative error code on failure
 */
int tls_configure_client_ssl(mbedtls_ssl_config *conf, mbedtls_x509_crt *ca,
                             const char *ca_file, int insecure);

/**
 * 从 bufferevent_mbedtls 取最近一次 TLS 错误码并写入调试日志。
 * 替代旧 OpenSSL 版本的 ERR_get_error() 错误队列遍历——mbedTLS 没有
 * 线程级错误队列，错误码由 libevent 保存在 bufferevent 上。
 *
 * @param bev      TLS bufferevent（非 TLS bev 时直接返回）
 * @param context  日志上下文描述字符串
 */
void tls_log_bev_error(struct bufferevent *bev, const char *context);

#endif /* XFRPC_TLS_H */
