/*
 * minifrpc —— MD5 摘要算法（RFC 1321）
 *
 * 标准实现，测试向量：
 *   MD5("")                            = d41d8cd98f00b204e9800998ecf8427e
 *   MD5("abc")                         = 900150983cd24fb0d6963f7d28e17f72
 *   MD5("The quick brown fox...")      = 9e107d9d372bb6826bd81d3542a419d6
 */

#include "md5.h"

#include <string.h>

/* 小端 32 位读/写 */
static uint32_t load32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static void store32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v);
    p[1] = (uint8_t)(v >> 8);
    p[2] = (uint8_t)(v >> 16);
    p[3] = (uint8_t)(v >> 24);
}

#define ROTL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

/* F/G/H/I 逻辑函数 */
#define F(x, y, z) (((x) & (y)) | (~(x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & ~(z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | ~(z)))

/* 每轮操作 */
#define STEP(f, a, b, c, d, x, t, s)        \
    do {                                     \
        (a) += f((b), (c), (d)) + (x) + (t); \
        (a) = ROTL((a), (s));                \
        (a) += (b);                          \
    } while (0)

typedef struct {
    uint32_t state[4];   /* A B C D */
    uint64_t count;      /* 已处理字节数 */
    uint8_t  buf[64];    /* 缓冲块 */
} md5_ctx_t;

static void md5_transform(md5_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t x[16];
    for (int i = 0; i < 16; i++) x[i] = load32(block + i * 4);

    uint32_t a = ctx->state[0];
    uint32_t b = ctx->state[1];
    uint32_t c = ctx->state[2];
    uint32_t d = ctx->state[3];

    /* 第 1 轮 */
    STEP(F, a, b, c, d, x[0],  0xd76aa478, 7);
    STEP(F, d, a, b, c, x[1],  0xe8c7b756, 12);
    STEP(F, c, d, a, b, x[2],  0x242070db, 17);
    STEP(F, b, c, d, a, x[3],  0xc1bdceee, 22);
    STEP(F, a, b, c, d, x[4],  0xf57c0faf, 7);
    STEP(F, d, a, b, c, x[5],  0x4787c62a, 12);
    STEP(F, c, d, a, b, x[6],  0xa8304613, 17);
    STEP(F, b, c, d, a, x[7],  0xfd469501, 22);
    STEP(F, a, b, c, d, x[8],  0x698098d8, 7);
    STEP(F, d, a, b, c, x[9],  0x8b44f7af, 12);
    STEP(F, c, d, a, b, x[10], 0xffff5bb1, 17);
    STEP(F, b, c, d, a, x[11], 0x895cd7be, 22);
    STEP(F, a, b, c, d, x[12], 0x6b901122, 7);
    STEP(F, d, a, b, c, x[13], 0xfd987193, 12);
    STEP(F, c, d, a, b, x[14], 0xa679438e, 17);
    STEP(F, b, c, d, a, x[15], 0x49b40821, 22);

    /* 第 2 轮 */
    STEP(G, a, b, c, d, x[1],  0xf61e2562, 5);
    STEP(G, d, a, b, c, x[6],  0xc040b340, 9);
    STEP(G, c, d, a, b, x[11], 0x265e5a51, 14);
    STEP(G, b, c, d, a, x[0],  0xe9b6c7aa, 20);
    STEP(G, a, b, c, d, x[5],  0xd62f105d, 5);
    STEP(G, d, a, b, c, x[10], 0x02441453, 9);
    STEP(G, c, d, a, b, x[15], 0xd8a1e681, 14);
    STEP(G, b, c, d, a, x[4],  0xe7d3fbc8, 20);
    STEP(G, a, b, c, d, x[9],  0x21e1cde6, 5);
    STEP(G, d, a, b, c, x[14], 0xc33707d6, 9);
    STEP(G, c, d, a, b, x[3],  0xf4d50d87, 14);
    STEP(G, b, c, d, a, x[8],  0x455a14ed, 20);
    STEP(G, a, b, c, d, x[13], 0xa9e3e905, 5);
    STEP(G, d, a, b, c, x[2],  0xfcefa3f8, 9);
    STEP(G, c, d, a, b, x[7],  0x676f02d9, 14);
    STEP(G, b, c, d, a, x[12], 0x8d2a4c8a, 20);

    /* 第 3 轮 */
    STEP(H, a, b, c, d, x[5],  0xfffa3942, 4);
    STEP(H, d, a, b, c, x[8],  0x8771f681, 11);
    STEP(H, c, d, a, b, x[11], 0x6d9d6122, 16);
    STEP(H, b, c, d, a, x[14], 0xfde5380c, 23);
    STEP(H, a, b, c, d, x[1],  0xa4beea44, 4);
    STEP(H, d, a, b, c, x[4],  0x4bdecfa9, 11);
    STEP(H, c, d, a, b, x[7],  0xf6bb4b60, 16);
    STEP(H, b, c, d, a, x[10], 0xbebfbc70, 23);
    STEP(H, a, b, c, d, x[13], 0x289b7ec6, 4);
    STEP(H, d, a, b, c, x[0],  0xeaa127fa, 11);
    STEP(H, c, d, a, b, x[3],  0xd4ef3085, 16);
    STEP(H, b, c, d, a, x[6],  0x04881d05, 23);
    STEP(H, a, b, c, d, x[9],  0xd9d4d039, 4);
    STEP(H, d, a, b, c, x[12], 0xe6db99e5, 11);
    STEP(H, c, d, a, b, x[15], 0x1fa27cf8, 16);
    STEP(H, b, c, d, a, x[2],  0xc4ac5665, 23);

    /* 第 4 轮 */
    STEP(I, a, b, c, d, x[0],  0xf4292244, 6);
    STEP(I, d, a, b, c, x[7],  0x432aff97, 10);
    STEP(I, c, d, a, b, x[14], 0xab9423a7, 15);
    STEP(I, b, c, d, a, x[5],  0xfc93a039, 21);
    STEP(I, a, b, c, d, x[12], 0x655b59c3, 6);
    STEP(I, d, a, b, c, x[3],  0x8f0ccc92, 10);
    STEP(I, c, d, a, b, x[10], 0xffeff47d, 15);
    STEP(I, b, c, d, a, x[1],  0x85845dd1, 21);
    STEP(I, a, b, c, d, x[8],  0x6fa87e4f, 6);
    STEP(I, d, a, b, c, x[15], 0xfe2ce6e0, 10);
    STEP(I, c, d, a, b, x[6],  0xa3014314, 15);
    STEP(I, b, c, d, a, x[13], 0x4e0811a1, 21);
    STEP(I, a, b, c, d, x[4],  0xf7537e82, 6);
    STEP(I, d, a, b, c, x[11], 0xbd3af235, 10);
    STEP(I, c, d, a, b, x[2],  0x2ad7d2bb, 15);
    STEP(I, b, c, d, a, x[9],  0xeb86d391, 21);

    ctx->state[0] += a;
    ctx->state[1] += b;
    ctx->state[2] += c;
    ctx->state[3] += d;
}

static void md5_update(md5_ctx_t *ctx, const uint8_t *data, size_t len)
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
        md5_transform(ctx, ctx->buf);
        data += need;
        len -= need;
    }

    while (len >= 64) {
        md5_transform(ctx, data);
        data += 64;
        len -= 64;
    }

    if (len > 0) {
        memcpy(ctx->buf, data, len);
    }
}

static void md5_final(md5_ctx_t *ctx, uint8_t out[MD5_DIGEST_LEN])
{
    uint64_t bit_len = ctx->count * 8;
    size_t used = (size_t)(ctx->count & 0x3f);
    size_t pad_len = (used < 56) ? (56 - used) : (120 - used);

    uint8_t tail[72];  /* 最多 64 填充 + 8 长度 */
    memset(tail, 0, sizeof(tail));
    tail[0] = 0x80;
    /* 追加 64 位长度（小端） */
    for (int i = 0; i < 8; i++) {
        tail[pad_len + i] = (uint8_t)(bit_len >> (8 * i));
    }
    md5_update(ctx, tail, pad_len + 8);

    for (int i = 0; i < 4; i++) {
        store32(out + i * 4, ctx->state[i]);
    }
}

void md5(const uint8_t *data, size_t len, uint8_t out[MD5_DIGEST_LEN])
{
    md5_ctx_t ctx;
    ctx.state[0] = 0x67452301;
    ctx.state[1] = 0xefcdab89;
    ctx.state[2] = 0x98badcfe;
    ctx.state[3] = 0x10325476;
    ctx.count = 0;
    memset(ctx.buf, 0, sizeof(ctx.buf));

    md5_update(&ctx, data, len);
    md5_final(&ctx, out);
}

void md5_hex(const uint8_t *data, size_t len, char out[33])
{
    uint8_t digest[MD5_DIGEST_LEN];
    md5(data, len, digest);
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < MD5_DIGEST_LEN; i++) {
        out[i * 2] = hex[digest[i] >> 4];
        out[i * 2 + 1] = hex[digest[i] & 0x0f];
    }
    out[32] = '\0';
}
