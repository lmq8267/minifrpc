/*
 * minifrpc —— AES-128 分组密码与 CFB-128 模式（FIPS 197）
 */

#ifndef MINIFRPC_AES_H
#define MINIFRPC_AES_H

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_LEN  16
#define AES128_KEY_LEN 16

/* AES-128 上下文（含轮密钥，11 轮 × 4 字） */
typedef struct {
    uint32_t rk[44];
} aes128_ctx;

/* 设置加密密钥 */
void aes128_set_encrypt_key(aes128_ctx *ctx, const uint8_t key[AES128_KEY_LEN]);

/* 加密/解密单个 16 字节块 */
void aes128_encrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_LEN],
                          uint8_t out[AES_BLOCK_LEN]);
void aes128_decrypt_block(const aes128_ctx *ctx, const uint8_t in[AES_BLOCK_LEN],
                          uint8_t out[AES_BLOCK_LEN]);

/* CFB-128 流式上下文（完整保存 iv、keystream、位置，可跨调用保持状态） */
typedef struct {
    aes128_ctx aes;
    uint8_t iv[AES_BLOCK_LEN];
    uint8_t ks[AES_BLOCK_LEN];  /* 当前 keystream 块 */
    size_t n;                   /* keystream 已用位置（0-15） */
} aes_cfb_ctx;

/* 初始化 CFB 上下文（key + iv） */
void aes_cfb_init(aes_cfb_ctx *c, const uint8_t key[AES128_KEY_LEN],
                  const uint8_t iv[AES_BLOCK_LEN]);

/* 流式加密/解密（加密与解密都基于 AES 加密方向，CFB 特性） */
void aes_cfb_encrypt(aes_cfb_ctx *c, const uint8_t *in, uint8_t *out, size_t len);
void aes_cfb_decrypt(aes_cfb_ctx *c, const uint8_t *in, uint8_t *out, size_t len);

#endif /* MINIFRPC_AES_H */
