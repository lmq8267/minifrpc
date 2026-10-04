/*
 * minifrpc —— base64 编解码（标准编码，与 Go encoding/base64 StdEncoding 一致）
 */

#ifndef MINIFRPC_BASE64_H
#define MINIFRPC_BASE64_H

#include <stddef.h>
#include <stdint.h>

/* 计算 base64 编码后的长度（含结尾 NUL） */
size_t base64_encode_len(size_t in_len);

/* 编码，out 需至少 base64_encode_len(in_len) 字节，返回输出长度（不含 NUL） */
size_t base64_encode(const uint8_t *in, size_t in_len, char *out);

/* 计算 base64 解码所需输出缓冲上限 */
size_t base64_decode_len(const char *in, size_t in_len);

/*
 * 解码，返回解码后字节数，-1 表示非法输入。
 * out 需至少 base64_decode_len(in, in_len) 字节。
 */
int base64_decode(const char *in, size_t in_len, uint8_t *out);

#endif /* MINIFRPC_BASE64_H */
