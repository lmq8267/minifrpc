/*
 * minifrpc —— SHA-1 摘要算法（FIPS 180-1）
 *
 * 标准实现，测试向量：
 *   SHA1("")    = da39a3ee5e6b4b0d3255bfef95601890afd80709
 *   SHA1("abc") = a9993e364706816aba3e25717850c26c9cd0d89d
 */

#include "sha1.h"

#include <string.h>

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

static uint32_t load32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
           ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void store32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)(v);
}

static void sha1_transform(sha1_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t w[80];
    for (int i = 0; i < 16; i++) w[i] = load32(block + i * 4);
    for (int i = 16; i < 80; i++) {
        w[i] = ROTL(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
    }

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];
    uint32_t e = ctx->state[4];

    for (int i = 0; i < 80; i++) {
        uint32_t f, k;
        if (i < 20) {
            f = (b & c) | ((~b) & d);
            k = 0x5a827999;
        } else if (i < 40) {
            f = b ^ c ^ d;
            k = 0x6ed9eba1;
        } else if (i < 60) {
            f = (b & c) | (b & d) | (c & d);
            k = 0x8f1bbcdc;
        } else {
            f = b ^ c ^ d;
            k = 0xca62c1d6;
        }
        uint32_t tmp = ROTL(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = ROTL(b, 30);
        b = a;
        a = tmp;
    }

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
    ctx->state[4] += e;
}

static void sha1_update_internal(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t used = (size_t)(ctx->count & 0x3f);
    ctx->count += len;

    if (used > 0) {
        size_t need = 64 - used;
        if (len < need) {
            memcpy(ctx->buf + used, data, len);
            return;
        }
        memcpy(ctx->buf + used, data, need);
        sha1_transform(ctx, ctx->buf);
        data += need;
        len -= need;
    }

    while (len >= 64) {
        sha1_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
    }
}

void sha1_init(sha1_ctx_t *ctx)
{
    ctx->state[0] = 0x67452301;
    ctx->state[1] = 0xefcdab89;
    ctx->state[2] = 0x98badcfe;
    ctx->state[3] = 0x10325476;
    ctx->state[4] = 0xc3d2e1f0;
    ctx->count = 0;
    memset(ctx->buf, 0, sizeof(ctx->buf));
}

void sha1_update(sha1_ctx_t *ctx, const uint8_t *data, size_t len)
{
    sha1_update_internal(ctx, data, len);
}

void sha1_final(sha1_ctx_t *ctx, uint8_t out[SHA1_DIGEST_LEN])
{
    uint64_t bit_len = ctx->count * 8;
    size_t used = (size_t)(ctx->count & 0x3f);
    size_t pad_len = (used < 56) ? (56 - used) : (120 - used);

    uint8_t tail[72];
    memset(tail, 0, sizeof(tail));
    tail[0] = 0x80;
    /* 64 位长度（大端） */
    for (int i = 0; i < 8; i++) {
        tail[pad_len + i] = (uint8_t)(bit_len >> (8 * (7 - i)));
    }
    sha1_update_internal(ctx, tail, pad_len + 8);

    for (int i = 0; i < 5; i++) {
        store32(out + i * 4, ctx->state[i]);
    }
}

void sha1(const uint8_t *data, size_t len, uint8_t out[SHA1_DIGEST_LEN])
{
    sha1_ctx_t ctx;
    sha1_init(&ctx);
    sha1_update(&ctx, data, len);
    sha1_final(&ctx, out);
}
