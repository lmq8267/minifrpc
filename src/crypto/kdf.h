/*
 * minifrpc —— HMAC-SHA1 与 PBKDF2（RFC 2104 / RFC 2898）
 */

#ifndef MINIFRPC_KDF_H
#define MINIFRPC_KDF_H

#include <stddef.h>
#include <stdint.h>

/* HMAC-SHA1，out 至少 20 字节 */
void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t out[20]);

/*
 * PBKDF2-HMAC-SHA1。
 * password / salt / iterations / dk_len 为标准参数，out 至少 dk_len 字节。
 */
void pbkdf2_hmac_sha1(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations,
                      uint8_t *out, size_t dk_len);

#endif /* MINIFRPC_KDF_H */
