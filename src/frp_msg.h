/*
 * minifrpc —— v1 消息帧与 frp 协议消息编解码
 *
 * v1 帧格式：1 字节 type + 8 字节大端 int64 长度 + JSON 体
 */

#ifndef MINIFRPC_FRP_MSG_H
#define MINIFRPC_FRP_MSG_H

#include <stddef.h>
#include <stdint.h>

#include "config.h"

/* ---- 消息类型字节（对齐 frp pkg/msg/msg.go） ---- */
#define FRP_MSG_LOGIN              'o'
#define FRP_MSG_LOGIN_RESP         '1'
#define FRP_MSG_NEW_PROXY          'p'
#define FRP_MSG_NEW_PROXY_RESP     '2'
#define FRP_MSG_CLOSE_PROXY        'c'
#define FRP_MSG_NEW_WORK_CONN      'w'
#define FRP_MSG_REQ_WORK_CONN      'r'
#define FRP_MSG_START_WORK_CONN    's'
#define FRP_MSG_NEW_VISITOR_CONN   'v'
#define FRP_MSG_NEW_VISITOR_RESP   '3'
#define FRP_MSG_PING               'h'
#define FRP_MSG_PONG               '4'
#define FRP_MSG_UDP_PACKET         'u'

/* JSON 体最大长度（golib msg/json 默认 10240） */
#define FRP_MAX_MSG_LEN 10240

/* ---- 认证 ---- */
/* 计算 privilege_key = hex(md5(token + 十进制时间戳))，out 至少 33 字节 */
void frp_auth_key(const char *token, int64_t timestamp, char out[33]);

/* ---- 帧编解码（明文字节流） ---- */
/*
 * 将 type + JSON 编码为一帧，写入 out（调用者保证 out 足够大）。
 * 返回帧总字节数。
 */
size_t frp_frame_encode(uint8_t type, const char *json, size_t json_len,
                        uint8_t *out, size_t out_cap);

/* ---- 消息构造（返回 malloc 的 JSON 字符串，调用者 free） ---- */
char *login_msg_build(const struct minifrpc_config *cfg, const char *run_id,
                      int64_t timestamp);
char *new_proxy_msg_build(const struct proxy_config *px);
char *new_work_conn_msg_build(const char *run_id, const char *token,
                              int64_t timestamp, int with_auth);
char *ping_msg_build(const char *token, int64_t timestamp, int with_auth);
char *udp_packet_msg_build(const uint8_t *content, size_t len,
                           const char *raddr_ip, int raddr_port);

/* 解析 Pong：含非空 error 时返回 1 并写入 out，否则返回 0 */
int pong_err_parse(const char *json, char *out, size_t out_sz);

/* ---- 消息解析结果 ---- */
struct login_resp {
    char version[64];
    char run_id[64];
    char error[256];
};

struct new_proxy_resp {
    char proxy_name[128];
    char remote_addr[128];
    char error[256];
};

struct start_work_conn {
    char proxy_name[128];
    char src_addr[64];
    char dst_addr[64];
    int  src_port;
    int  dst_port;
    char error[256];
};

struct udp_packet {
    uint8_t *content;
    size_t   content_len;
    char     raddr_ip[64];
    int      raddr_port;
};

/* 解析函数，返回 0 成功，-1 失败 */
int login_resp_parse(const char *json, struct login_resp *out);
int new_proxy_resp_parse(const char *json, struct new_proxy_resp *out);
int start_work_conn_parse(const char *json, struct start_work_conn *out);
int udp_packet_parse(const char *json, struct udp_packet *out);

/* 释放 udp_packet 中动态分配的内容 */
void udp_packet_free(struct udp_packet *p);

#endif /* MINIFRPC_FRP_MSG_H */
