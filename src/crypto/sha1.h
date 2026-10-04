/*
 * minifrpc —— SHA-1 摘要算法（FIPS 180-1 标准实现）
 */

#ifndef MINIFRPC_SHA1_H
#define MINIFRPC_SHA1_H

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_LEN 20
#define SHA1_BLOCK_LEN  64

/* SHA-1 上下文 */
typedef struct {
    uint32_t state[5];
    uint64_t count;
    uint8_t  buf[64];
} sha1_ctx_t;

void sha1_init(sha1_ctx_t *ctx);
void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len);
void sha1_final(sha1_ctx_t *ctx, uint8_t out[SHA1_DIGEST_LEN]);

/* 一次性计算 SHA-1，out 至少 20 字节 */
void sha1(const uint8_t *data, size_t len, uint8_t out[SHA1_DIGEST_LEN]);

#endif /* MINIFRPC_SHA1_H */
