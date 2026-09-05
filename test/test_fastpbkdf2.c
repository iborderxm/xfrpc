/* PBKDF2-HMAC-SHA1 standalone test (mbedTLS backend).
 * Not part of the xfrpc build; compile manually with:
 *   cc test_fastpbkdf2.c -lmbedcrypto -o test_fastpbkdf2
 */

#include <mbedtls/md.h>
#include <mbedtls/pkcs5.h>
#include <string.h>
#include <stdint.h>
#include <stdio.h>

void pbkdf2_key(const uint8_t *password, size_t password_len,
                const uint8_t *salt, size_t salt_len,
                uint32_t iterations, uint8_t *out, size_t out_len) {
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
    mbedtls_md_context_t md_ctx;

    mbedtls_md_init(&md_ctx);
    mbedtls_md_setup(&md_ctx, md_info, 1);
    mbedtls_pkcs5_pbkdf2_hmac(&md_ctx,
                              password, password_len,
                              salt, salt_len,
                              iterations,
                              (uint32_t)out_len, out);
    mbedtls_md_free(&md_ctx);
}

int main() {
    const char *password = "password";
    const uint8_t salt[] = "saltsalt";
    uint8_t key[16]; // size of the derived key

    pbkdf2_key((const uint8_t *)password, strlen(password),
               salt, sizeof(salt) - 1, 1000, key, sizeof(key));

    printf("Derived key: ");
    for (size_t i = 0; i < sizeof(key); i++) {
        printf("%02x", key[i]);
    }
    printf("\n");

    return 0;
}
