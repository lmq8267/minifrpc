/*
 * minifrpc —— HMAC-SHA1 与 PBKDF2 实现
 *
 * 测试向量：
 *   HMAC-SHA1(key="Jefe", data="what do ya want for nothing?")
 *     = effcdf6ae5eb2fa2d27416d5f184df9c259a7c79
 *   PBKDF2-HMAC-SHA1("password","salt",1,20)
 *     = 0c60c80f961f0e71f3a9b524af6012062fe037a6
 *   PBKDF2-HMAC-SHA1("password","salt",2,20)
 *     = ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957
 */

#include "kdf.h"
#include "sha1.h"

#include <string.h>

#define SHA1_BLOCK 64

void hmac_sha1(const uint8_t *key, size_t key_len,
               const uint8_t *data, size_t data_len,
               uint8_t out[20])
{
    uint8_t k[SHA1_BLOCK];
    uint8_t ipad[SHA1_BLOCK];
    uint8_t opad[SHA1_BLOCK];
    uint8_t inner[SHA1_DIGEST_LEN];

    memset(k, 0, sizeof(k));
    if (key_len > SHA1_BLOCK) {
        sha1(key, key_len, k);   /* 长密钥先散列 */
    } else {
        memcpy(k, key, key_len);
    }

    for (int i = 0; i < SHA1_BLOCK; i++) {
        ipad[i] = k[i] ^ 0x36;
        opad[i] = k[i] ^ 0x5c;
    }

    /* inner = SHA1(ipad || data) */
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, ipad, SHA1_BLOCK);
    sha1_update(&ctx, data, data_len);
    sha1_final(&ctx, inner);

    /* out = SHA1(opad || inner) */
    sha1_init(&ctx);
    sha1_update(&ctx, opad, SHA1_BLOCK);
    sha1_update(&ctx, inner, SHA1_DIGEST_LEN);
    sha1_final(&ctx, out);
}

void pbkdf2_hmac_sha1(const uint8_t *password, size_t pw_len,
                      const uint8_t *salt, size_t salt_len,
                      uint32_t iterations,
                      uint8_t *out, size_t dk_len)
{
    uint8_t u[20];
    uint8_t t[20];
    uint32_t block_idx = 1;
    size_t pos = 0;

    while (pos < dk_len) {
        /* U1 = HMAC(password, salt || INT_BE(block_idx)) */
        uint8_t block[4];
        block[0] = (uint8_t)(block_idx >> 24);
        block[1] = (uint8_t)(block_idx >> 16);
        block[2] = (uint8_t)(block_idx >> 8);
        block[3] = (uint8_t)(block_idx);

        /* 计算 U1 */
        sha1_ctx_t ctx;
        uint8_t ipad[SHA1_BLOCK], opad[SHA1_BLOCK], k[SHA1_BLOCK];
        memset(k, 0, sizeof(k));
        if (pw_len > SHA1_BLOCK) {
            sha1(password, pw_len, k);
        } else {
            memcpy(k, password, pw_len);
        }
        for (int i = 0; i < SHA1_BLOCK; i++) {
            ipad[i] = k[i] ^ 0x36;
            opad[i] = k[i] ^ 0x5c;
        }

        /* U1 */
        uint8_t inner[20];
        sha1_init(&ctx);
        sha1_update(&ctx, ipad, SHA1_BLOCK);
        sha1_update(&ctx, salt, salt_len);
        sha1_update(&ctx, block, 4);
        sha1_final(&ctx, inner);

        sha1_init(&ctx);
        sha1_update(&ctx, opad, SHA1_BLOCK);
        sha1_update(&ctx, inner, 20);
        sha1_final(&ctx, u);
        memcpy(t, u, 20);

        /* U2..Uc */
        for (uint32_t j = 1; j < iterations; j++) {
            sha1_init(&ctx);
            sha1_update(&ctx, ipad, SHA1_BLOCK);
            sha1_update(&ctx, u, 20);
            sha1_final(&ctx, inner);

            sha1_init(&ctx);
            sha1_update(&ctx, opad, SHA1_BLOCK);
            sha1_update(&ctx, inner, 20);
            sha1_final(&ctx, u);

            for (int b = 0; b < 20; b++) t[b] ^= u[b];
        }

        size_t copy = dk_len - pos;
        if (copy > 20) copy = 20;
        memcpy(out + pos, t, copy);
        pos += copy;
        block_idx++;
    }
}
