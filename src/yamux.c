/*
 * minifrpc —— yamux 客户端协议实现（hashicorp/yamux 兼容）
 *
 * 帧头 12 字节：version(1) + type(1) + flags(2) + stream_id(4) + length(4)，大端。
 * 流建立（SYN/ACK）、窗口更新、FIN/RST 都走 typeWindowUpdate 帧；
 * 业务数据走 typeData 帧。
 */

#include "yamux.h"
#include "log.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* 帧头 12 字节，全部大端 */
static void frame_write(struct yamux_session *s, uint8_t type, uint16_t flags,
                        uint32_t stream_id, uint32_t length, const uint8_t *payload)
{
    uint8_t hdr[12];
    hdr[0] = 0;                       /* version */
    hdr[1] = type;
    hdr[2] = (uint8_t)(flags >> 8);
    hdr[3] = (uint8_t)(flags & 0xff);
    hdr[4] = (uint8_t)(stream_id >> 24);
    hdr[5] = (uint8_t)(stream_id >> 16);
    hdr[6] = (uint8_t)(stream_id >> 8);
    hdr[7] = (uint8_t)(stream_id & 0xff);
    hdr[8] = (uint8_t)(length >> 24);
    hdr[9] = (uint8_t)(length >> 16);
    hdr[10] = (uint8_t)(length >> 8);
    hdr[11] = (uint8_t)(length & 0xff);

    bufferevent_write(s->bev, hdr, 12);
    if (length > 0 && payload) {
        bufferevent_write(s->bev, payload, length);
    }
}

static struct yamux_stream *find_stream(struct yamux_session *s, uint32_t id)
{
    for (struct yamux_stream *st = s->streams; st; st = st->next) {
        if (st->id == id) return st;
    }
    return NULL;
}

static void stream_free(struct yamux_stream *st);

/* 发送窗口内可发送的数据 */
static void stream_flush(struct yamux_stream *st)
{
    if (!st->session || st->closed) return;

    while (evbuffer_get_length(st->txq) > 0 && st->send_window > 0) {
        size_t avail = evbuffer_get_length(st->txq);
        size_t send_len = avail;
        if (send_len > st->send_window) send_len = st->send_window;

        uint8_t *buf = malloc(send_len ? send_len : 1);
        evbuffer_remove(st->txq, buf, send_len);
        frame_write(st->session, YAMUX_TYPE_DATA, 0, st->id, (uint32_t)send_len, buf);
        st->send_window -= (uint32_t)send_len;
        free(buf);
    }
}

/* 处理收到的一帧 */
static void yamux_handle_frame(struct yamux_session *s, uint8_t type, uint16_t flags,
                               uint32_t stream_id, uint32_t length, const uint8_t *payload)
{
    struct yamux_stream *st;

    switch (type) {
    case YAMUX_TYPE_WINDOW_UPDATE:
        st = find_stream(s, stream_id);
        if (!st) return;

        if (flags & YAMUX_FLAG_RST) {
            st->closed = 1;
            if (st->on_close) st->on_close(st, st->ctx);
            stream_free(st);
            return;
        }

        /* 窗口增量（ACK 帧的 length 也是窗口增量） */
        st->send_window += length;

        if (flags & YAMUX_FLAG_ACK) {
            if (!st->established) {
                st->established = 1;
                if (st->on_established) st->on_established(st, st->ctx);
            }
        }

        if (flags & YAMUX_FLAG_FIN) {
            st->closed = 1;
        }

        stream_flush(st);

        if (st->closed) {
            if (st->on_close) st->on_close(st, st->ctx);
            stream_free(st);
        }
        break;

    case YAMUX_TYPE_DATA: {
        st = find_stream(s, stream_id);
        if (!st) return;

        if (flags & YAMUX_FLAG_RST) {
            st->closed = 1;
            if (st->on_close) st->on_close(st, st->ctx);
            stream_free(st);
            return;
        }
        if (flags & YAMUX_FLAG_FIN) {
            st->closed = 1;
        }

        if (length > 0) {
            evbuffer_add(st->rbuf, payload, length);
            /* 接收窗口更新 */
            if (st->recv_window > length) {
                st->recv_window -= length;
            } else {
                st->recv_window = 0;
            }
            if (st->recv_window < YAMUX_INITIAL_WINDOW) {
                uint32_t delta = YAMUX_MAX_WINDOW - st->recv_window;
                frame_write(s, YAMUX_TYPE_WINDOW_UPDATE, 0, st->id, delta, NULL);
                st->recv_window = YAMUX_MAX_WINDOW;
            }
            if (st->on_data) st->on_data(st, st->ctx);
        }

        if (st->closed) {
            if (st->on_close) st->on_close(st, st->ctx);
            stream_free(st);
        }
        break;
    }

    case YAMUX_TYPE_PING:
        if (flags & YAMUX_FLAG_SYN) {
            frame_write(s, YAMUX_TYPE_PING, YAMUX_FLAG_ACK, 0, length, payload);
        }
        break;

    case YAMUX_TYPE_GOAWAY:
        log_debug("服务器已关闭会话");
        s->closed = 1;
        break;

    default:
        log_debug("收到未知帧类型: %d", type);
        break;
    }
}

static void yamux_read_cb(struct bufferevent *bev, void *ctx)
{
    struct yamux_session *s = ctx;
    struct evbuffer *in = bufferevent_get_input(bev);

    while (1) {
        if (evbuffer_get_length(in) < 12) return;

        uint8_t hdr[12];
        evbuffer_copyout(in, hdr, 12);
        uint8_t type = hdr[1];
        uint16_t flags = (uint16_t)((hdr[2] << 8) | hdr[3]);
        uint32_t stream_id = ((uint32_t)hdr[4] << 24) | ((uint32_t)hdr[5] << 16) |
                             ((uint32_t)hdr[6] << 8) | (uint32_t)hdr[7];
        uint32_t length = ((uint32_t)hdr[8] << 24) | ((uint32_t)hdr[9] << 16) |
                          ((uint32_t)hdr[10] << 8) | (uint32_t)hdr[11];

        /* 只有 Data 帧携带 payload；WindowUpdate/Ping/GoAway 的 length
         * 分别是窗口增量/pingID/错误码，无 payload */
        size_t payload_len = (type == YAMUX_TYPE_DATA) ? (size_t)length : 0;
        if (evbuffer_get_length(in) < 12 + payload_len) return;

        evbuffer_drain(in, 12);
        uint8_t *payload = NULL;
        if (payload_len > 0) {
            payload = malloc(payload_len);
            evbuffer_remove(in, payload, payload_len);
        }
        yamux_handle_frame(s, type, flags, stream_id, length, payload);
        free(payload);
    }
}

/* keepalive：定期主动发 Ping，保活（对齐 frp tcpMuxKeepaliveInterval 默认 30s） */
static void yamux_keepalive_cb(evutil_socket_t fd, short what, void *ctx)
{
    (void)fd;
    (void)what;
    struct yamux_session *s = ctx;
    if (s->closed || !s->bev) return;

    uint32_t ping_id = (uint32_t)rand();
    frame_write(s, YAMUX_TYPE_PING, YAMUX_FLAG_SYN, 0, ping_id, NULL);

    struct timeval tv = { YAMUX_KEEPALIVE_INTERVAL, 0 };
    evtimer_add(s->keepalive_ev, &tv);
}

static void yamux_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    struct yamux_session *s = ctx;
    if (what & BEV_EVENT_CONNECTED) {
        s->connected = 1;
        /* 启动 keepalive 定时器 */
        if (s->keepalive_ev) {
            struct timeval tv = { YAMUX_KEEPALIVE_INTERVAL, 0 };
            evtimer_add(s->keepalive_ev, &tv);
        }
        if (s->on_connect) s->on_connect(s, s->ctx);
    } else if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        log_warn("与服务器连接断开");
        s->closed = 1;
        if (s->keepalive_ev) evtimer_del(s->keepalive_ev);
        bufferevent_free(bev);
        s->bev = NULL;
        if (s->on_close) s->on_close(s, s->ctx);
    }
}

struct yamux_session *yamux_client(struct event_base *base, const char *host, int port)
{
    struct yamux_session *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->base = base;
    s->next_id = 1;  /* 客户端流 ID 从 1 开始（奇数递增） */

    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        log_error("无法解析服务器地址 %s", host);
        free(s);
        return NULL;
    }

    struct bufferevent *bev = NULL;
    for (rp = res; rp; rp = rp->ai_next) {
        bev = bufferevent_socket_new(base, -1, BEV_OPT_CLOSE_ON_FREE);
        if (!bev) continue;
        if (bufferevent_socket_connect(bev, rp->ai_addr, rp->ai_addrlen) < 0) {
            bufferevent_free(bev);
            bev = NULL;
            continue;
        }
        break;
    }
    freeaddrinfo(res);

    if (!bev) {
        free(s);
        return NULL;
    }

    s->bev = bev;
    s->keepalive_ev = evtimer_new(base, yamux_keepalive_cb, s);
    bufferevent_setcb(bev, yamux_read_cb, NULL, yamux_event_cb, s);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    return s;
}

struct yamux_stream *yamux_open_stream(struct yamux_session *s)
{
    struct yamux_stream *st = calloc(1, sizeof(*st));
    if (!st) return NULL;

    st->id = s->next_id;
    s->next_id += 2;  /* 奇数递增 */
    st->session = s;
    st->rbuf = evbuffer_new();
    st->txq = evbuffer_new();
    st->send_window = YAMUX_INITIAL_WINDOW;
    st->recv_window = YAMUX_INITIAL_WINDOW;

    /* 加入链表 */
    st->next = s->streams;
    s->streams = st;

    /* 发 SYN：typeWindowUpdate + flagSYN，length 为窗口增量 */
    uint32_t delta = YAMUX_MAX_WINDOW - YAMUX_INITIAL_WINDOW;
    frame_write(s, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_SYN, st->id, delta, NULL);
    st->recv_window = YAMUX_MAX_WINDOW;

    return st;
}

int yamux_stream_write(struct yamux_stream *s, const uint8_t *data, size_t len)
{
    if (!s || s->closed || !s->session) return -1;
    if (len == 0) return 0;
    evbuffer_add(s->txq, data, len);
    stream_flush(s);
    return 0;
}

void yamux_stream_close(struct yamux_stream *s)
{
    if (!s || s->closed) return;
    s->closed = 1;
    stream_flush(s);
    if (s->session && s->session->bev) {
        frame_write(s->session, YAMUX_TYPE_WINDOW_UPDATE, YAMUX_FLAG_FIN, s->id, 0, NULL);
    }
}

static void stream_free(struct yamux_stream *st)
{
    struct yamux_session *s = st->session;
    if (s) {
        struct yamux_stream **pp = &s->streams;
        while (*pp) {
            if (*pp == st) {
                *pp = st->next;
                break;
            }
            pp = &(*pp)->next;
        }
    }
    if (st->rbuf) evbuffer_free(st->rbuf);
    if (st->txq) evbuffer_free(st->txq);
    free(st);
}

void yamux_session_free(struct yamux_session *s)
{
    if (!s) return;
    struct yamux_stream *st = s->streams;
    while (st) {
        struct yamux_stream *next = st->next;
        if (st->rbuf) evbuffer_free(st->rbuf);
        if (st->txq) evbuffer_free(st->txq);
        free(st);
        st = next;
    }
    if (s->keepalive_ev) event_free(s->keepalive_ev);
    if (s->bev) bufferevent_free(s->bev);
    free(s);
}
