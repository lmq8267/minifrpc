/*
 * minifrpc —— MD5 摘要算法（RFC 1321 标准实现）
 */

#ifndef MINIFRPC_MD5_H
#define MINIFRPC_MD5_H

#include <stddef.h>
#include <stdint.h>

#define MD5_DIGEST_LEN 16

/* 一次性计算 MD5，out 至少 16 字节 */
void md5(const uint8_t *data, size_t len, uint8_t out[MD5_DIGEST_LEN]);

/* 计算 MD5 并转小写十六进制字符串（out 至少 33 字节，含结尾 NUL） */
void md5_hex(const uint8_t *data, size_t len, char out[33]);

#endif /* MINIFRPC_MD5_H */
