/*
 * minifrpc —— Proxy Protocol v2 头构造实现
 */

#include "proxyproto.h"

#include <arpa/inet.h>
#include <string.h>

int proxyproto_v2_build(int udp, const char *src_ip, int src_port,
                        const char *dst_ip, int dst_port,
                        uint8_t *out, int out_cap)
{
    uint8_t src4[4], dst4[4];
    uint8_t src6[16], dst6[16];
    int is_v4;

    if (inet_pton(AF_INET, src_ip, src4) == 1 &&
        inet_pton(AF_INET, dst_ip, dst4) == 1) {
        is_v4 = 1;
    } else if (inet_pton(AF_INET6, src_ip, src6) == 1 &&
               inet_pton(AF_INET6, dst_ip, dst6) == 1) {
        is_v4 = 0;
    } else {
        /* 地址不可识别，回退到 IPv4（按 0.0.0.0 处理） */
        is_v4 = 1;
        memset(src4, 0, 4);
        memset(dst4, 0, 4);
    }

    /* 地址块长度 */
    int addr_len = is_v4 ? 12 : 36;
    if (out_cap < 16 + addr_len) return -1;

    /* 签名 */
    static const uint8_t sig[12] = {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
    };
    memcpy(out, sig, 12);
    out[12] = 0x21;  /* ver=2, cmd=PROXY */
    /* 地址族/协议 */
    if (is_v4) {
        out[13] = udp ? 0x12 : 0x11;
    } else {
        out[13] = udp ? 0x22 : 0x21;
    }
    out[14] = (uint8_t)(addr_len >> 8);
    out[15] = (uint8_t)(addr_len & 0xff);

    int pos = 16;
    if (is_v4) {
        memcpy(out + pos, src4, 4); pos += 4;
        memcpy(out + pos, dst4, 4); pos += 4;
    } else {
        memcpy(out + pos, src6, 16); pos += 16;
        memcpy(out + pos, dst6, 16); pos += 16;
    }
    out[pos++] = (uint8_t)(src_port >> 8);
    out[pos++] = (uint8_t)(src_port & 0xff);
    out[pos++] = (uint8_t)(dst_port >> 8);
    out[pos++] = (uint8_t)(dst_port & 0xff);

    return pos;
}
