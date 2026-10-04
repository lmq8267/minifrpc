/*
 * minifrpc —— yamux 客户端协议（hashicorp/yamux 兼容）
 *
 * 帧头 12 字节：version(1) + type(1) + flags(2) + stream_id(4) + length(4)，大端。
 * frpc 只发起流（客户端流 ID 为奇数），不接收服务端发起的流。
 */

#ifndef MINIFRPC_YAMUX_H
#define MINIFRPC_YAMUX_H

#include <event2/buffer.h>
#include <event2/bufferevent.h>
#include <event2/event.h>

#include <stdint.h>

/* 帧类型 */
#define YAMUX_TYPE_DATA          0
#define YAMUX_TYPE_WINDOW_UPDATE 1
#define YAMUX_TYPE_PING          2
#define YAMUX_TYPE_GOAWAY        3

/* 帧标志 */
#define YAMUX_FLAG_SYN 0x1
#define YAMUX_FLAG_ACK 0x2
#define YAMUX_FLAG_FIN 0x4
#define YAMUX_FLAG_RST 0x8

/* 窗口大小 */
#define YAMUX_INITIAL_WINDOW (256 * 1024)   /* 初始窗口 256KB */
#define YAMUX_MAX_WINDOW     (6 * 1024 * 1024) /* 最大窗口 6MB（对齐 frp MaxStreamWindowSize） */

/* keepalive 间隔（秒，对齐 frp tcpMuxKeepaliveInterval 默认值） */
#define YAMUX_KEEPALIVE_INTERVAL 30

struct yamux_session;
struct yamux_stream;

typedef void (*yamux_stream_cb)(struct yamux_stream *s, void *ctx);

struct yamux_stream {
    uint32_t id;
    struct yamux_session *session;
    struct evbuffer *rbuf;        /* 读缓冲（对端发来的数据） */
    struct evbuffer *txq;         /* 待发送队列（窗口不足时暂存） */
    int established;              /* SYN 已收到 ACK */
    int closed;
    void *ctx;
    yamux_stream_cb on_established;  /* ACK 到达时回调（可空） */
    yamux_stream_cb on_data;         /* 数据到达时回调 */
    yamux_stream_cb on_close;        /* 流关闭时回调（可空） */
    uint32_t recv_window;
    uint32_t send_window;
    struct yamux_stream *next;
};

struct yamux_session {
    struct event_base *base;
    struct bufferevent *bev;
    struct yamux_stream *streams;  /* 流链表 */
    uint32_t next_id;              /* 下一个客户端流 ID（奇数递增） */
    int connected;
    int closed;
    struct event *keepalive_ev;  /* keepalive 定时器（定期发 Ping） */
    void (*on_connect)(struct yamux_session *s, void *ctx);
    void (*on_close)(struct yamux_session *s, void *ctx);  /* 底层连接断开时回调（可空） */
    void *ctx;
};

/*
 * 创建 yamux 客户端会话：建立 TCP 连接，连接成功后回调 on_connect。
 * 返回会话对象（失败返回 NULL）。
 */
struct yamux_session *yamux_client(struct event_base *base, const char *host, int port);

/* 打开一个流（发 SYN），返回流对象 */
struct yamux_stream *yamux_open_stream(struct yamux_session *s);

/* 写数据到流（封装 Data 帧，受发送窗口限制，超出部分进队列） */
int yamux_stream_write(struct yamux_stream *s, const uint8_t *data, size_t len);

/* 关闭流（发 FIN） */
void yamux_stream_close(struct yamux_stream *s);

/* 销毁会话及其所有流 */
void yamux_session_free(struct yamux_session *s);

#endif /* MINIFRPC_YAMUX_H */
