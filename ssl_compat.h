// SPDX-License-Identifier: GPL-3.0-only
/*
 * SSL/TLS compatibility header.
 *
 * Always includes real OpenSSL headers for crypto (EVP, RAND, MD5) and
 * TLS (SSL) APIs.  OpenSSL is the only TLS backend of this project:
 * libevent's bufferevent_openssl_socket_new requires real OpenSSL's
 * struct ssl_st, and the crypto layer (PBKDF2, AES-128-CFB, MD5) uses
 * the OpenSSL EVP interface.
 */

#ifndef XFRPC_SSL_COMPAT_H
#define XFRPC_SSL_COMPAT_H

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/md5.h>

#endif /* XFRPC_SSL_COMPAT_H */
