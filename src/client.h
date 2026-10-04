/*
 * minifrpc —— 客户端核心结构体定义
 */

#ifndef MINIFRPC_CLIENT_H
#define MINIFRPC_CLIENT_H

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include <netinet/in.h>
#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "config.h"
#include "crypto/aes.h"
#include "yamux.h"

/* 连接加密流（读/写方向各一个 CFB 上下文） */
struct cfb_stream {
    aes_cfb_ctx read;            /* 读方向（解密） */
    aes_cfb_ctx write;           /* 写方向（加密） */
    int iv_read_init;            /* 是否已读取首 IV */
    int iv_write_init;           /* 是否已写入首 IV */
};

/* 一个连接（封装底层字节流 + 加密 + 帧缓冲） */
struct frp_conn {
    int use_yamux;               /* 1=yamux 流，0=独立 TCP */
    struct bufferevent *bev;     /* 直连模式的 bufferevent */
    struct yamux_stream *ys;     /* yamux 模式的流 */
    struct cfb_stream cfb;
    int cfb_enabled;             /* 是否启用加密（控制连接登录后为 1） */
    struct evbuffer *plain;      /* 解密后的明文帧缓冲 */
    int frame_mode;              /* 1=帧模式（type+len+json），0=数据模式（裸字节） */
    void (*on_frame)(struct frp_conn *c, uint8_t type, const char *json);
    void (*on_data)(struct frp_conn *c, struct evbuffer *data);
    void (*on_error)(struct frp_conn *c);  /* 协议错误时回调（可空） */
    void *ctx;
};

struct frp_client;
struct proxy;

/* 工作隧道（TCP/UDP 共用）：一个 work 连接 + 本地连接 */
struct tunnel {
    struct frp_conn work;
    int is_udp;                  /* 1=UDP 代理，0=TCP 代理 */
    struct proxy *px;

    /* TCP 字段 */
    struct bufferevent *local_bev;
    struct evbuffer *pending;    /* 本地连接未就绪时暂存 work 方向的数据 */
    int started;                 /* 本地连接是否已就绪 */

    /* UDP 字段 */
    int udp_fd;                  /* 本地 UDP socket */
    struct event *udp_ev;        /* 本地 UDP 读事件 */
    struct event *udp_ping_ev;   /* UDP work 连接保活 Ping 定时器 */
    struct sockaddr_storage local_addr;
    socklen_t local_addrlen;
    struct sockaddr_storage raddr;  /* 外部客户端地址（用于回包） */
    socklen_t raddrlen;
    int has_raddr;
    int pp_sent;                 /* 是否已发送过 PROXY 头（UDP 首包） */

    /* Proxy Protocol v2（TCP） */
    int pp_enabled;
    char pp_src_ip[64];
    int pp_src_port;
    char pp_dst_ip[64];
    int pp_dst_port;

    struct tunnel *next;         /* 全局隧道链表 */
};

/* 单个代理 */
struct proxy {
    struct proxy_config *cfg;
    struct frp_client *client;
    int registered;
};

/* 客户端全局 */
struct frp_client {
    struct minifrpc_config *cfg;
    struct event_base *base;
    struct frp_conn ctl;         /* 控制连接 */
    struct yamux_session *session; /* yamux 会话（tcpMux 开启时使用） */
    char run_id[64];             /* 登录返回的 run_id */
    uint8_t login_key[16];       /* 控制连接 AES 密钥（PBKDF2 派生） */
    int logged_in;
    int ever_logged_in;          /* 是否曾经登录成功（用于重连后登录失败仍持续重试） */
    struct proxy *proxies;
    int proxy_count;
    struct tunnel *tunnels;      /* 活跃隧道链表（退出时统一清理） */
    struct event *reconnect_ev;  /* 断线重连定时器 */
    struct event *heartbeat_ev;  /* 应用层心跳定时器（heartbeat_interval>0 时启用） */
    time_t last_ping;            /* 上次发送 Ping 的时间 */
    time_t last_pong;            /* 上次收到 Pong 的时间 */
    int stopping;                /* 收到退出信号后置 1，不再重连 */
};

/* 断线重连间隔（秒） */
#define RECONNECT_INTERVAL_SEC 5

/* 应用层心跳定时器检查粒度（秒） */
#define HEARTBEAT_TICK_SEC 1

/* UDP work 连接保活 Ping 间隔（秒，对齐 Go frpc 客户端的 30s） */
#define UDP_WORK_PING_INTERVAL 30

/* 生成随机字节 */
void frp_random_bytes(uint8_t *out, int len);

/* 格式化 host:port（IPv6 自动加方括号），out 至少 300 字节 */
void frp_format_hostport(char *out, size_t out_sz, const char *host, int port);

/* 初始化 CFB 加密流（用 16 字节密钥） */
void cfb_init(struct cfb_stream *s, const uint8_t key[16]);

/* 加密写：将明文写入 conn 的 output（若加密则 CFB 加密） */
int conn_write(struct frp_conn *c, const uint8_t *data, size_t len);

/* 写一条消息帧（type + json） */
int conn_write_msg(struct frp_conn *c, uint8_t type, const char *json);

/* 从明文帧缓冲解析出所有完整帧并回调 on_frame */
void conn_dispatch_frames(struct frp_conn *c);

/* 建立 TCP 连接（返回 bufferevent，连接成功触发 BEV_EVENT_CONNECTED，失败返回 NULL） */
struct bufferevent *bev_connect(struct event_base *base, const char *host, int port);

/* 启动客户端主循环（阻塞），返回 0 正常退出 */
int client_run(struct minifrpc_config *cfg);

#endif /* MINIFRPC_CLIENT_H */
