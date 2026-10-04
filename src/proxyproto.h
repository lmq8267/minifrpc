/*
 * minifrpc —— Proxy Protocol v2 头构造（HAProxy PROXY protocol v2）
 *
 * 头格式（无 TLV）：
 *   签名 12B: 0D 0A 0D 0A 00 0D 0A 51 55 49 54 0A
 *   版本/命令 1B: 0x21 (ver=2, cmd=PROXY)
 *   地址族/协议 1B: 0x11 TCPv4 / 0x12 UDPv4 / 0x21 TCPv6 / 0x22 UDPv6
 *   长度 2B (BE)
 *   地址块: srcIP + dstIP + srcPort(2B BE) + dstPort(2B BE)
 */

#ifndef MINIFRPC_PROXYPROTO_H
#define MINIFRPC_PROXYPROTO_H

#include <stdint.h>

/* 构造 PROXY v2 头。udp 为 1 表示 UDP 协议族，0 表示 TCP。
 * 返回头长度，失败返回 -1。out 需至少 52 字节。 */
int proxyproto_v2_build(int udp, const char *src_ip, int src_port,
                        const char *dst_ip, int dst_port,
                        uint8_t *out, int out_cap);

#endif /* MINIFRPC_PROXYPROTO_H */
