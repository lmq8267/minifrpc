/*
 * minifrpc —— base64 编解码实现
 */

#include "base64.h"

static const char g_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_val(char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

size_t base64_encode_len(size_t in_len)
{
    return ((in_len + 2) / 3) * 4 + 1;
}

size_t base64_encode(const uint8_t *in, size_t in_len, char *out)
{
    size_t i = 0, o = 0;
    while (i + 3 <= in_len) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8) | in[i + 2];
        out[o++] = g_table[(v >> 18) & 0x3f];
        out[o++] = g_table[(v >> 12) & 0x3f];
        out[o++] = g_table[(v >> 6) & 0x3f];
        out[o++] = g_table[v & 0x3f];
        i += 3;
    }
    if (in_len - i == 1) {
        uint32_t v = (uint32_t)in[i] << 16;
        out[o++] = g_table[(v >> 18) & 0x3f];
        out[o++] = g_table[(v >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (in_len - i == 2) {
        uint32_t v = ((uint32_t)in[i] << 16) | ((uint32_t)in[i + 1] << 8);
        out[o++] = g_table[(v >> 18) & 0x3f];
        out[o++] = g_table[(v >> 12) & 0x3f];
        out[o++] = g_table[(v >> 6) & 0x3f];
        out[o++] = '=';
    }
    out[o] = '\0';
    return o;
}

size_t base64_decode_len(const char *in, size_t in_len)
{
    /* 去掉尾部 padding */
    size_t pad = 0;
    if (in_len > 0 && in[in_len - 1] == '=') pad++;
    if (in_len > 1 && in[in_len - 2] == '=') pad++;
    return (in_len / 4) * 3 - pad;
}

int base64_decode(const char *in, size_t in_len, uint8_t *out)
{
    size_t o = 0;
    uint32_t acc = 0;
    int bits = 0;
    size_t pad = 0;

    for (size_t i = 0; i < in_len; i++) {
        char c = in[i];
        if (c == '=') {
            pad++;
            continue;
        }
        if (c == '\n' || c == '\r' || c == ' ') continue;
        int v = base64_val(c);
        if (v < 0) return -1;
        acc = (acc << 6) | (uint32_t)v;
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out[o++] = (uint8_t)((acc >> bits) & 0xff);
        }
    }
    return (int)o;
}
