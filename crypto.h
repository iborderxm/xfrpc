
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */


#ifndef XFRPC_CRYPTO_H
#define XFRPC_CRYPTO_H

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <mbedtls/aes.h>

#include "common.h"

/**
 * @brief Structure for FRP encryption/decryption operations
 */
struct frp_coder {
	uint8_t     key[16];    /**< Encryption/decryption key */
	char        *salt;      /**< Salt value for key derivation */
	uint8_t     iv[16];     /**< Initialization vector */
	char        *token;     /**< Authentication token */
	int         iv_sent;    /**< Whether IV has been sent (golib compat) */
};

/**
 * @brief Get the size of encryption block
 * @return Size of the encryption block
 */
size_t get_encrypt_block_size(void);

/**
 * @brief Decrypt data using the specified decoder
 * @param enc_data Encrypted data buffer
 * @param enc_len Length of encrypted data
 * @param decoder Decoder structure
 * @param ret Pointer to store decrypted data
 * @return Size of decrypted data
 */
size_t decrypt_data(const uint8_t *enc_data, size_t enc_len, struct frp_coder *decoder, uint8_t **ret);

/**
 * @brief Check if encoder is initialized
 * @return 1 if initialized, 0 otherwise
 */
int is_encoder_inited(void);

/**
 * @brief Check if decoder is initialized
 * @return 1 if initialized, 0 otherwise
 */
int is_decoder_inited(void);

/**
 * @brief Initialize main encoder
 * @return Pointer to initialized encoder structure
 */
struct frp_coder *init_main_encoder(void);

/**
 * @brief Initialize main decoder with given IV
 * @param iv Initialization vector
 * @return Pointer to initialized decoder structure
 */
struct frp_coder *init_main_decoder(const uint8_t *iv);

/**
 * @brief Create new coder with token and salt
 * @param token Authentication token
 * @param salt Salt for key derivation
 * @return Pointer to new coder structure
 */
struct frp_coder *new_coder(const char *token, const char *salt);

/**
 * @brief Encrypt key using token and salt
 * @param token Authentication token
 * @param token_len Token length
 * @param salt Salt value
 * @param key Key buffer
 * @param key_len Key length
 * @return Pointer to encrypted key
 */
uint8_t *encrypt_key(const char *token, size_t token_len, const char *salt, uint8_t *key, size_t key_len);

/**
 * @brief Encrypt initialization vector
 * @param iv_buf IV buffer
 * @param iv_len IV length
 * @return Pointer to encrypted IV
 */
uint8_t *encrypt_iv(uint8_t *iv_buf, size_t iv_len);

/**
 * @brief Encrypt data using specified encoder
 * @param src_data Source data buffer
 * @param srclen Source data length
 * @param encoder Encoder structure
 * @param ret Pointer to store encrypted data
 * @return Size of encrypted data
 */
size_t encrypt_data(const uint8_t *src_data, size_t srclen, struct frp_coder *encoder, uint8_t **ret);

/**
 * @brief Get main encoder instance
 * @return Pointer to main encoder
 */
struct frp_coder *get_main_encoder(void);

/**
 * @brief Get main decoder instance
 * @return Pointer to main decoder
 */
struct frp_coder *get_main_decoder(void);

/**
 * @brief Get block size
 * @return Block size value
 */
size_t get_block_size(void);

/**
 * @brief Free encoder structure
 * @param encoder Pointer to encoder structure
 */
void free_encoder(struct frp_coder *encoder);

/**
 * @brief Free EVP cipher context
 */
void free_crypto_resources(void);

/* ============================================================
 * mbedTLS 加密原语（frp 协议加密基础）
 * ============================================================ */

/**
 * @brief PBKDF2-HMAC-SHA1 密钥派生（对应 frp/golang 的 pbkdf2.Key，SHA1，64 轮）
 * @param password      口令（如 auth token / secret key）
 * @param password_len  口令长度
 * @param salt          盐值（frp 中为 "crypto" 或协议默认盐）
 * @param salt_len      盐值长度
 * @param iterations    迭代次数（frp 固定 64）
 * @param key           输出密钥缓冲区
 * @param key_len       期望密钥长度（AES-128 为 16）
 * @return 0 成功，非 0 为 mbedTLS 错误码
 */
int xfrpc_pbkdf2_sha1(const char *password, size_t password_len,
                      const unsigned char *salt, size_t salt_len,
                      unsigned int iterations,
                      unsigned char *key, size_t key_len);

/**
 * @brief AES-128-CFB128 流式加解密上下文
 *
 * 与 OpenSSL EVP_aes_128_cfb() 的连续流语义一致：
 * IV 在 update 之间随密文/明文流连续滚动，iv_off 记录块内偏移。
 * 加解密均使用 AES 加密密钥表（CFB 模式本身只使用正向加密变换）。
 */
struct xfrpc_cfb_ctx {
	mbedtls_aes_context aes;       /**< AES 密钥表 */
	unsigned char       iv[16];    /**< 当前 IV（随流滚动更新） */
	size_t              iv_off;    /**< IV 块内字节偏移 */
	int                 encrypt;   /**< 1=加密(MBEDTLS_AES_ENCRYPT)，0=解密(MBEDTLS_AES_DECRYPT) */
	int                 inited;    /**< 是否已设置密钥 */
};

/**
 * @brief 初始化 CFB 上下文（置零）
 */
void xfrpc_cfb_init(struct xfrpc_cfb_ctx *ctx);

/**
 * @brief 设置 AES-128-CFB128 密钥与初始 IV
 * @param ctx     上下文（需先 xfrpc_cfb_init）
 * @param key     16 字节 AES-128 密钥
 * @param iv      16 字节初始 IV
 * @param encrypt 1=加密，0=解密
 * @return 0 成功，非 0 为 mbedTLS 错误码
 */
int xfrpc_cfb_set_key(struct xfrpc_cfb_ctx *ctx,
                      const unsigned char key[16],
                      const unsigned char iv[16],
                      int encrypt);

/**
 * @brief 加/解密一段数据（流语义：可多次调用，IV 状态连续；支持原地加解密）
 * @param ctx 上下文
 * @param out 输出缓冲区（长度 >= len，可与 in 相同）
 * @param in  输入数据
 * @param len 数据长度
 * @return 0 成功，非 0 为 mbedTLS 错误码
 */
int xfrpc_cfb_update(struct xfrpc_cfb_ctx *ctx,
                     unsigned char *out,
                     const unsigned char *in, size_t len);

/**
 * @brief 释放 CFB 上下文内部资源
 */
void xfrpc_cfb_free(struct xfrpc_cfb_ctx *ctx);

#endif // XFRPC_CRYPTO_H
