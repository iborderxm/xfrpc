// SPDX-License-Identifier: GPL-3.0-only
/*
 * SSL/TLS compatibility header.
 *
 * mbedTLS (3.6.x) is the only TLS/crypto backend of this project:
 *   - TLS transport: libevent's bufferevent_mbedtls_* (libevent >= 2.2)
 *     wraps mbedtls_ssl_context, see tls.c
 *   - Crypto primitives: PBKDF2-HMAC-SHA1 (mbedtls_pkcs5),
 *     AES-128-CFB128 (mbedtls_aes), MD5 (mbedtls_md5)
 *   - Random data: the global CTR_DRBG instance behind xfrpc_random()
 *     (implemented in utils.c)
 *
 * This header pulls in the mbedTLS headers needed by the crypto layer.
 * TLS transport code (tls.c) includes tls.h which additionally provides
 * the libevent bufferevent_mbedtls integration.
 */

#ifndef XFRPC_SSL_COMPAT_H
#define XFRPC_SSL_COMPAT_H

#include <mbedtls/aes.h>
#include <mbedtls/md.h>
#include <mbedtls/md5.h>
#include <mbedtls/pkcs5.h>
#include <mbedtls/error.h>

/**
 * 全局随机数生成函数（实现在 utils.c）。
 *
 * 内部基于 mbedtls entropy + CTR_DRBG，首次调用时惰性初始化。
 * 函数签名与 mbedTLS 的 f_rng 回调一致，因此可直接传给
 * mbedtls_ssl_conf_rng() / mbedtls_pk_parse_key_file() 等接口；
 * 独立使用时 p_rng 传 NULL 即可。
 *
 * @param p_rng      mbedTLS 回调上下文（未使用，传 NULL）
 * @param output     随机数输出缓冲区
 * @param output_len 需要的随机数字节数
 * @return 0 成功，非 0 为 mbedTLS 错误码
 */
int xfrpc_random(void *p_rng, unsigned char *output, size_t output_len);

#endif /* XFRPC_SSL_COMPAT_H */
