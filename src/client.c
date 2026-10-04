/*
 * minifrpc —— 客户端核心实现
 *
 * 控制连接（登录/注册代理/ReqWorkConn 处理）+ work 连接 + TCP 隧道。
 * 支持 tcpMux=yamux 与直连（tcpMux=false）两种传输层。
 */

#include "client.h"
#include "log.h"
#include "frp_msg.h"
#include "proxyproto.h"
#include "crypto/kdf.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

/* PBKDF2 盐（frp 固定为 "frp"） */
#define FRP_SALT "frp"

/* ---- 工具函数 ---- */

void frp_random_bytes(uint8_t *out, int len)
{
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        for (int i = 0; i < len; i++) out[i] = (uint8_t)(rand() & 0xff);
        return;
    }
    ssize_t n = 0;
    while (n < len) {
        ssize_t r = read(fd, out + n, (size_t)(len - n));
        if (r <= 0) break;
        n += r;
    }
    close(fd);
}

/* 格式化 host:port：含 ":" 的（IPv6 字面量）加方括号，便于日志辨认 */
void frp_format_hostport(char *out, size_t out_sz, const char *host, int port)
{
    if (host && strchr(host, ':')) {
        snprintf(out, out_sz, "[%s]:%d", host, port);
    } else {
        snprintf(out, out_sz, "%s:%d", host ? host : "", port);
    }
}

/* 建立 TCP 连接并返回 bufferevent（连接成功后触发 BEV_EVENT_CONNECTED） */
struct bufferevent *bev_connect(struct event_base *base, const char *host, int port)
{
    struct addrinfo hints, *res = NULL, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", port);

    if (getaddrinfo(host, portstr, &hints, &res) != 0) {
        log_error("无法解析服务器地址 %s", host);
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
    return bev;
}

/* ---- 加密流 ---- */

void cfb_init(struct cfb_stream *s, const uint8_t key[16])
{
    aes128_set_encrypt_key(&s->read.aes, key);
    aes128_set_encrypt_key(&s->write.aes, key);
    s->read.n = 0;
    s->write.n = 0;
    s->iv_read_init = 0;
    s->iv_write_init = 0;
}

/* ---- 底层 I/O 抽象 ---- */

static int conn_raw_write(struct frp_conn *c, const uint8_t *data, size_t len)
{
    if (c->use_yamux) {
        return yamux_stream_write(c->ys, data, len);
    }
    return bufferevent_write(c->bev, data, len);
}

static struct evbuffer *conn_input(struct frp_conn *c)
{
    if (c->use_yamux) {
        return c->ys->rbuf;
    }
    return bufferevent_get_input(c->bev);
}

/* ---- 连接写 ---- */

int conn_write(struct frp_conn *c, const uint8_t *data, size_t len)
{
    if (len == 0) return 0;

    if (!c->cfb_enabled) {
        return conn_raw_write(c, data, len);
    }

    /* 首次加密写先写 16 字节随机 IV（明文） */
    if (!c->cfb.iv_write_init) {
        frp_random_bytes(c->cfb.write.iv, 16);
        c->cfb.write.n = 0;
        c->cfb.iv_write_init = 1;
        if (conn_raw_write(c, c->cfb.write.iv, 16) < 0) return -1;
    }

    uint8_t *enc = malloc(len);
    if (!enc) return -1;
    aes_cfb_encrypt(&c->cfb.write, data, enc, len);
    int r = conn_raw_write(c, enc, len);
    free(enc);
    return r;
}

int conn_write_msg(struct frp_conn *c, uint8_t type, const char *json)
{
    size_t json_len = strlen(json);
    uint8_t frame[9 + FRP_MAX_MSG_LEN];
    size_t n = frp_frame_encode(type, json, json_len, frame, sizeof(frame));
    if (n == 0) return -1;
    return conn_write(c, frame, n);
}

/* ---- 连接读 ---- */

/* 从明文帧缓冲解析一帧，成功 0，数据不足 1，错误 -1 */
static int read_frame_from_evbuffer(struct evbuffer *in, uint8_t *type, char **json_out)
{
    size_t avail = evbuffer_get_length(in);
    if (avail < 9) return 1;

    uint8_t hdr[9];
    evbuffer_copyout(in, hdr, 9);
    *type = hdr[0];
    uint64_t len = 0;
    for (int i = 0; i < 8; i++) len = (len << 8) | hdr[1 + i];
    if (len > FRP_MAX_MSG_LEN) {
        log_error("收到的消息长度异常: %llu", (unsigned long long)len);
        return -1;
    }
    if (avail < 9 + len) return 1;

    evbuffer_drain(in, 9);
    char *json = malloc((size_t)len + 1);
    if (!json) return -1;
    evbuffer_remove(in, json, (size_t)len);
    json[len] = '\0';
    *json_out = json;
    return 0;
}

/* 从 src 缓冲分发：帧模式逐帧解析，数据模式转发 */
static void conn_dispatch(struct frp_conn *c, struct evbuffer *src)
{
    while (1) {
        if (c->frame_mode) {
            uint8_t type;
            char *json;
            int r = read_frame_from_evbuffer(src, &type, &json);
            if (r == 1) return;  /* 数据不足 */
            if (r < 0) {
                if (c->use_yamux) {
                    yamux_stream_close(c->ys);
                } else if (c->bev) {
                    bufferevent_free(c->bev);
                    c->bev = NULL;
                }
                if (c->on_error) c->on_error(c);
                return;
            }
            int was_cfb = c->cfb_enabled;
            if (c->on_frame) c->on_frame(c, type, json);
            free(json);
            if (c->cfb_enabled != was_cfb) return;
            continue;
        } else {
            if (c->on_data && evbuffer_get_length(src) > 0) {
                c->on_data(c, src);
                evbuffer_drain(src, evbuffer_get_length(src));
            }
            return;
        }
    }
}

/* 将连接 input 中的密文/明文按模式分发 */
static void conn_process_input(struct frp_conn *c)
{
    struct evbuffer *input = conn_input(c);

    if (c->cfb_enabled) {
        if (!c->cfb.iv_read_init) {
            if (evbuffer_get_length(input) < 16) return;
            evbuffer_remove(input, c->cfb.read.iv, 16);
            c->cfb.read.n = 0;
            c->cfb.iv_read_init = 1;
        }
        size_t len = evbuffer_get_length(input);
        if (len > 0) {
            uint8_t *tmp = malloc(len);
            uint8_t *dec = malloc(len);
            evbuffer_copyout(input, tmp, len);
            aes_cfb_decrypt(&c->cfb.read, tmp, dec, len);
            evbuffer_add(c->plain, dec, len);
            evbuffer_drain(input, len);
            free(tmp);
            free(dec);
        }
        conn_dispatch(c, c->plain);
    } else {
        conn_dispatch(c, input);
        if (c->cfb_enabled) {
            conn_process_input(c);
        }
    }
}

/* ---- 前向声明 ---- */
static void ctl_read_cb(struct bufferevent *bev, void *ctx);
static void ctl_event_cb(struct bufferevent *bev, short what, void *ctx);
static void work_read_cb(struct bufferevent *bev, void *ctx);
static void work_event_cb(struct bufferevent *bev, short what, void *ctx);
static void local_read_cb(struct bufferevent *bev, void *ctx);
static void local_event_cb(struct bufferevent *bev, short what, void *ctx);
static void work_on_data(struct frp_conn *c, struct evbuffer *data);
static int work_connect(struct frp_client *cl);
static struct proxy *find_proxy(struct frp_client *cl, const char *name);
static void send_login(struct frp_client *cl);
static void register_all_proxies(struct frp_client *cl);
static void ctl_on_frame(struct frp_conn *c, uint8_t type, const char *json);
static void on_session_connect(struct yamux_session *s, void *ctx);
static void on_ctl_stream_data(struct yamux_stream *ys, void *ctx);
static void udp_tunnel_start(struct tunnel *t, struct start_work_conn *swc);
static void udp_work_on_frame(struct frp_conn *c, uint8_t type, const char *json);
static void udp_local_read_cb(int fd, short what, void *ctx);
static void tunnel_free(struct tunnel *t);
static void work_on_error(struct frp_conn *c);
static void ctl_on_error(struct frp_conn *c);
static void sigint_cb(int sig, short what, void *ctx);
static void schedule_reconnect(struct frp_client *cl);
static void reconnect_cb(int fd, short what, void *ctx);
static void on_session_close(struct yamux_session *s, void *ctx);
static void ctl_heartbeat_cb(int fd, short what, void *ctx);
static void udp_ping_cb(int fd, short what, void *ctx);

/* ---- 控制连接 ---- */

/* 发送登录消息 */
static void send_login(struct frp_client *cl)
{
    int64_t now = (int64_t)time(NULL);
    char *json = login_msg_build(cl->cfg, "", now);
    if (json) {
        conn_write_msg(&cl->ctl, FRP_MSG_LOGIN, json);
        free(json);
        log_info("已发送登录请求");
    }
}

/* 注册所有代理 */
static void register_all_proxies(struct frp_client *cl)
{
    for (int i = 0; i < cl->proxy_count; i++) {
        struct proxy *px = &cl->proxies[i];
        char *json = new_proxy_msg_build(px->cfg);
        if (!json) continue;
        conn_write_msg(&cl->ctl, FRP_MSG_NEW_PROXY, json);
        free(json);
        log_info("已发送代理注册请求 [%s] 类型=%s 远程端口=%d",
                 px->cfg->name, px->cfg->type, px->cfg->remote_port);
    }
}

/* 控制连接登录成功后处理 */
static void on_login_success(struct frp_client *cl, const char *run_id)
{
    snprintf(cl->run_id, sizeof(cl->run_id), "%s", run_id);
    cl->logged_in = 1;
    cl->ever_logged_in = 1;

    /* 重置心跳计时基准（每次登录/重连后重新计时） */
    cl->last_ping = time(NULL);
    cl->last_pong = cl->last_ping;

    pbkdf2_hmac_sha1((const uint8_t *)cl->cfg->token, strlen(cl->cfg->token),
                     (const uint8_t *)FRP_SALT, strlen(FRP_SALT), 64,
                     cl->login_key, 16);

    cfb_init(&cl->ctl.cfb, cl->login_key);
    cl->ctl.cfb_enabled = 1;

    log_info("登录成功，run_id=%s", run_id);
    register_all_proxies(cl);
}

/* 处理控制连接的消息帧 */
static void ctl_on_frame(struct frp_conn *c, uint8_t type, const char *json)
{
    struct frp_client *cl = c->ctx;

    switch (type) {
    case FRP_MSG_LOGIN_RESP: {
        struct login_resp resp;
        login_resp_parse(json, &resp);
        if (resp.error[0]) {
            log_error("登录失败: %s", resp.error);
            /* 首次登录失败按 loginFailExit 处理；重连后登录失败则继续重试（对齐 Go） */
            if (!cl->ever_logged_in && cl->cfg->login_fail_exit) {
                event_base_loopexit(cl->base, NULL);
            } else {
                schedule_reconnect(cl);
            }
            return;
        }
        on_login_success(cl, resp.run_id);
        break;
    }
    case FRP_MSG_REQ_WORK_CONN:
        work_connect(cl);
        break;
    case FRP_MSG_NEW_PROXY_RESP: {
        struct new_proxy_resp resp;
        new_proxy_resp_parse(json, &resp);
        if (resp.error[0]) {
            log_error("代理 [%s] 注册失败: %s", resp.proxy_name, resp.error);
        } else {
            /* frps 返回的 remote_addr 常为「:端口」，补上服务端地址显示完整 */
            const char *p = strrchr(resp.remote_addr, ':');
            const char *port = (p && *(p + 1)) ? p + 1 : resp.remote_addr;
            char hp[300];
            frp_format_hostport(hp, sizeof(hp), cl->cfg->server_addr, atoi(port));
            log_info("代理 [%s] 注册成功，远程地址 %s", resp.proxy_name, hp);
        }
        break;
    }
    case FRP_MSG_PONG: {
        char perr[256];
        if (pong_err_parse(json, perr, sizeof(perr))) {
            /* Pong 携带 error 视为心跳异常，断开重连（对齐 Go handlePong） */
            log_error("收到带错误的 Pong: %s", perr);
            schedule_reconnect(cl);
            return;
        }
        cl->last_pong = time(NULL);
        log_debug("收到 Pong 心跳响应");
        break;
    }
    case FRP_MSG_PING:
        /* frps 控制连接不会主动发 Ping（Go 版仅由客户端发 Ping），此处保留为兼容处理 */
        conn_write_msg(&cl->ctl, FRP_MSG_PONG, "{}");
        break;
    default:
        log_warn("收到未知控制消息类型: 0x%02x", type);
        break;
    }
}

/* ---- 控制连接：yamux 模式 ---- */

static void on_session_connect(struct yamux_session *s, void *ctx)
{
    struct frp_client *cl = ctx;
    char hp[300];
    frp_format_hostport(hp, sizeof(hp), cl->cfg->server_addr, cl->cfg->server_port);
    log_info("已连接服务器 %s", hp);

    /* 打开控制流 */
    struct yamux_stream *ys = yamux_open_stream(s);
    if (!ys) {
        log_error("打开控制流失败");
        event_base_loopexit(cl->base, NULL);
        return;
    }

    memset(&cl->ctl, 0, sizeof(cl->ctl));
    cl->ctl.use_yamux = 1;
    cl->ctl.ys = ys;
    cl->ctl.frame_mode = 1;
    cl->ctl.on_frame = ctl_on_frame;
    cl->ctl.on_error = ctl_on_error;
    cl->ctl.ctx = cl;
    cl->ctl.plain = evbuffer_new();

    ys->ctx = &cl->ctl;
    ys->on_data = on_ctl_stream_data;

    /* 立即发送登录请求（yamux 客户端发 SYN 后不等待 ACK） */
    send_login(cl);
}

static void on_ctl_stream_data(struct yamux_stream *ys, void *ctx)
{
    (void)ys;
    struct frp_conn *c = ctx;
    conn_process_input(c);
}

/* ---- 控制连接：直连模式 ---- */

static void ctl_read_cb(struct bufferevent *bev, void *ctx)
{
    (void)bev;
    struct frp_client *cl = ctx;
    conn_process_input(&cl->ctl);
}

static void ctl_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    struct frp_client *cl = ctx;
    if (what & BEV_EVENT_CONNECTED) {
        char hp[300];
        frp_format_hostport(hp, sizeof(hp), cl->cfg->server_addr, cl->cfg->server_port);
        log_info("已连接服务器 %s", hp);
        send_login(cl);
    } else if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        log_warn("控制连接断开");
        bufferevent_free(bev);
        cl->ctl.bev = NULL;
        schedule_reconnect(cl);
    }
}

/* 建立控制连接（直连模式） */
static int ctl_connect(struct frp_client *cl)
{
    struct bufferevent *bev = bev_connect(cl->base, cl->cfg->server_addr, cl->cfg->server_port);
    if (!bev) {
        char hp[300];
        frp_format_hostport(hp, sizeof(hp), cl->cfg->server_addr, cl->cfg->server_port);
        log_error("无法连接服务器 %s", hp);
        return -1;
    }

    memset(&cl->ctl, 0, sizeof(cl->ctl));
    cl->ctl.bev = bev;
    cl->ctl.frame_mode = 1;
    cl->ctl.on_frame = ctl_on_frame;
    cl->ctl.on_error = ctl_on_error;
    cl->ctl.ctx = cl;
    cl->ctl.plain = evbuffer_new();

    bufferevent_setcb(bev, ctl_read_cb, NULL, ctl_event_cb, cl);
    bufferevent_enable(bev, EV_READ | EV_WRITE);
    return 0;
}

/* ---- work 连接（TCP 隧道） ---- */

static struct proxy *find_proxy(struct frp_client *cl, const char *name)
{
    for (int i = 0; i < cl->proxy_count; i++) {
        if (strcmp(cl->proxies[i].cfg->name, name) == 0) {
            return &cl->proxies[i];
        }
    }
    return NULL;
}

/* work 连接收到 StartWorkConn 后，建立隧道 */
static void tunnel_start(struct tunnel *t, struct start_work_conn *swc)
{
    struct proxy *px = t->px;
    struct frp_client *cl = px->client;

    struct bufferevent *lbev = bev_connect(cl->base, px->cfg->local_ip, px->cfg->local_port);
    if (!lbev) {
        log_error("代理 [%s] 连接本地服务 %s:%d 失败",
                  px->cfg->name, px->cfg->local_ip, px->cfg->local_port);
        tunnel_free(t);
        return;
    }

    t->local_bev = lbev;
    t->pending = evbuffer_new();
    t->started = 0;

    /* Proxy Protocol v2 配置 */
    if (px->cfg->proxy_protocol_version[0] && swc->src_addr[0] && swc->src_port != 0) {
        t->pp_enabled = 1;
        snprintf(t->pp_src_ip, sizeof(t->pp_src_ip), "%s", swc->src_addr);
        t->pp_src_port = swc->src_port;
        snprintf(t->pp_dst_ip, sizeof(t->pp_dst_ip), "%s",
                 swc->dst_addr[0] ? swc->dst_addr : "127.0.0.1");
        t->pp_dst_port = swc->dst_port;
    }

    /* work 连接切换到数据模式 */
    t->work.frame_mode = 0;
    t->work.on_data = work_on_data;

    bufferevent_setcb(lbev, local_read_cb, NULL, local_event_cb, t);
    bufferevent_enable(lbev, EV_READ | EV_WRITE);

    log_info("代理 [%s] 隧道建立: %s:%d -> 本地 %s:%d",
             px->cfg->name, swc->src_addr, swc->src_port,
             px->cfg->local_ip, px->cfg->local_port);
}

/* work 连接收到 StartWorkConn 帧（登录后数据前） */
static void work_on_frame(struct frp_conn *c, uint8_t type, const char *json)
{
    struct tunnel *t = c->ctx;

    if (type == FRP_MSG_START_WORK_CONN) {
        struct start_work_conn swc;
        start_work_conn_parse(json, &swc);
        if (swc.error[0]) {
            log_error("工作连接建立失败: %s", swc.error);
            tunnel_free(t);
            return;
        }
        struct frp_client *cl = t->px->client;
        struct proxy *px = find_proxy(cl, swc.proxy_name);
        if (!px) {
            log_error("工作连接引用了未知代理: %s", swc.proxy_name);
            tunnel_free(t);
            return;
        }
        t->px = px;
        if (strcmp(px->cfg->type, "udp") == 0) {
            t->is_udp = 1;
            udp_tunnel_start(t, &swc);
        } else {
            tunnel_start(t, &swc);
        }
    }
}

/* work 连接数据转发到本地 */
static void work_on_data(struct frp_conn *c, struct evbuffer *data)
{
    struct tunnel *t = c->ctx;
    if (!t->started || !t->local_bev) {
        if (t->pending) {
            evbuffer_add_buffer(t->pending, data);
        }
        return;
    }
    bufferevent_write_buffer(t->local_bev, data);
}

/* 本地服务数据转发到 work */
static void local_read_cb(struct bufferevent *bev, void *ctx)
{
    struct tunnel *t = ctx;
    struct evbuffer *in = bufferevent_get_input(bev);
    size_t n = evbuffer_get_length(in);
    if (n == 0) return;
    if (t->work.use_yamux) {
        /* 通过 yamux 流转发 */
        yamux_stream_write(t->work.ys, evbuffer_pullup(in, -1), n);
        evbuffer_drain(in, n);
    } else if (t->work.bev) {
        bufferevent_write_buffer(t->work.bev, in);
    }
}

/* ---- UDP 隧道 ---- */

/*
 * UDP work 连接保活：frps 对 UDP work 连接设置 60s 读超时，客户端必须每 30s
 * 发一次 Ping 保活（对齐 Go frpc client/proxy/udp.go 的 heartbeatFn）。
 */
static void udp_ping_cb(int fd, short what, void *ctx)
{
    (void)fd;
    (void)what;
    struct tunnel *t = ctx;
    conn_write_msg(&t->work, FRP_MSG_PING, "{}");
    struct timeval tv = { UDP_WORK_PING_INTERVAL, 0 };
    evtimer_add(t->udp_ping_ev, &tv);
}

static void udp_tunnel_start(struct tunnel *t, struct start_work_conn *swc)
{
    (void)swc;
    struct proxy *px = t->px;
    struct frp_client *cl = px->client;

    /* 先解析本地服务地址（支持 IPv4/IPv6） */
    struct addrinfo hints, *res = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    char portstr[16];
    snprintf(portstr, sizeof(portstr), "%d", px->cfg->local_port);
    if (getaddrinfo(px->cfg->local_ip, portstr, &hints, &res) != 0) {
        log_error("代理 [%s] 解析本地地址 %s 失败", px->cfg->name, px->cfg->local_ip);
        tunnel_free(t);
        return;
    }
    memcpy(&t->local_addr, res->ai_addr, res->ai_addrlen);
    t->local_addrlen = res->ai_addrlen;
    int family = res->ai_family;  /* 按解析结果的地址族创建 socket（兼容 IPv6） */
    freeaddrinfo(res);

    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0) {
        log_error("代理 [%s] 创建本地 UDP socket 失败", px->cfg->name);
        tunnel_free(t);
        return;
    }
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags | O_NONBLOCK);

    t->udp_fd = fd;

    /* work 连接保持帧模式，处理 UDPPacket 帧 */
    t->work.frame_mode = 1;
    t->work.on_frame = udp_work_on_frame;

    /* 本地 UDP 读事件 */
    t->udp_ev = event_new(cl->base, fd, EV_READ | EV_PERSIST, udp_local_read_cb, t);
    event_add(t->udp_ev, NULL);

    /* UDP work 连接保活定时器（定期发 Ping，避免 frps 60s 读超时关闭） */
    t->udp_ping_ev = evtimer_new(cl->base, udp_ping_cb, t);
    struct timeval ping_tv = { UDP_WORK_PING_INTERVAL, 0 };
    evtimer_add(t->udp_ping_ev, &ping_tv);

    log_info("代理 [%s] UDP 隧道建立，本地 %s:%d", px->cfg->name,
             px->cfg->local_ip, px->cfg->local_port);
}

/* 从 sockaddr 提取 IP 字符串和端口 */
static void sockaddr_to_ip_port(const struct sockaddr_storage *ss, char *ip, size_t ip_sz, int *port)
{
    if (ss->ss_family == AF_INET) {
        const struct sockaddr_in *sin = (const struct sockaddr_in *)ss;
        inet_ntop(AF_INET, &sin->sin_addr, ip, (socklen_t)ip_sz);
        *port = ntohs(sin->sin_port);
    } else if (ss->ss_family == AF_INET6) {
        const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)ss;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, (socklen_t)ip_sz);
        *port = ntohs(sin6->sin6_port);
    } else {
        ip[0] = '\0';
        *port = 0;
    }
}

/* work 连接收到 UDPPacket 帧 */
static void udp_work_on_frame(struct frp_conn *c, uint8_t type, const char *json)
{
    struct tunnel *t = c->ctx;

    if (type == FRP_MSG_UDP_PACKET) {
        struct udp_packet p;
        udp_packet_parse(json, &p);
        if (p.content && p.content_len > 0 && t->udp_fd >= 0) {
            /* 解析外部客户端地址（raddr），用于回包 */
            char portstr[16];
            snprintf(portstr, sizeof(portstr), "%d", p.raddr_port);
            struct addrinfo hints, *res = NULL;
            memset(&hints, 0, sizeof(hints));
            hints.ai_family = AF_UNSPEC;
            hints.ai_socktype = SOCK_DGRAM;
            if (getaddrinfo(p.raddr_ip, portstr, &hints, &res) == 0) {
                memcpy(&t->raddr, res->ai_addr, res->ai_addrlen);
                t->raddrlen = res->ai_addrlen;
                t->has_raddr = 1;
                freeaddrinfo(res);
            }

            /* Proxy Protocol v2：首个数据报前拼接头 */
            if (t->px->cfg->proxy_protocol_version[0] && !t->pp_sent && t->has_raddr) {
                char src_ip[64];
                int src_port;
                sockaddr_to_ip_port(&t->raddr, src_ip, sizeof(src_ip), &src_port);
                uint8_t pp[52];
                int pn = proxyproto_v2_build(1, src_ip, src_port,
                                             t->px->cfg->local_ip, t->px->cfg->local_port,
                                             pp, sizeof(pp));
                if (pn > 0) {
                    uint8_t *combined = malloc((size_t)pn + p.content_len);
                    memcpy(combined, pp, (size_t)pn);
                    memcpy(combined + pn, p.content, p.content_len);
                    sendto(t->udp_fd, combined, (size_t)pn + p.content_len, 0,
                           (struct sockaddr *)&t->local_addr, t->local_addrlen);
                    free(combined);
                    t->pp_sent = 1;
                    udp_packet_free(&p);
                    return;
                }
            }

            sendto(t->udp_fd, p.content, p.content_len, 0,
                   (struct sockaddr *)&t->local_addr, t->local_addrlen);
        }
        udp_packet_free(&p);
    }
    /* 其他类型（如服务端不回 Pong）忽略：UDP work 连接由本端单向发 Ping 保活 */
}

/* 本地 UDP 回包，封 UDPPacket 发回 */
static void udp_local_read_cb(int fd, short what, void *ctx)
{
    (void)what;
    struct tunnel *t = ctx;
    uint8_t buf[65536];
    ssize_t n = recv(fd, buf, sizeof(buf), 0);
    if (n <= 0) return;
    if (!t->has_raddr) return;

    char ip[64];
    int port;
    sockaddr_to_ip_port(&t->raddr, ip, sizeof(ip), &port);
    char *json = udp_packet_msg_build(buf, (size_t)n, ip, port);
    if (json) {
        conn_write_msg(&t->work, FRP_MSG_UDP_PACKET, json);
        free(json);
    }
}

/* 协议错误处理 */
static void work_on_error(struct frp_conn *c)
{
    struct tunnel *t = c->ctx;
    tunnel_free(t);
}

static void ctl_on_error(struct frp_conn *c)
{
    struct frp_client *cl = c->ctx;
    log_warn("控制连接协议错误，准备重连");
    schedule_reconnect(cl);
}

/* SIGINT/SIGTERM 信号处理：优雅退出事件循环 */
static void sigint_cb(int sig, short what, void *ctx)
{
    (void)sig;
    (void)what;
    struct frp_client *cl = ctx;
    cl->stopping = 1;  /* 阻止断线重连 */
    log_info("收到退出信号，正在关闭...");
    event_base_loopexit(cl->base, NULL);
}

/* 重置连接状态（重连前调用，释放旧的控制连接/会话/隧道） */
static void client_reset(struct frp_client *cl)
{
    /* 释放所有隧道（含其中引用的 yamux 流） */
    while (cl->tunnels) {
        tunnel_free(cl->tunnels);
    }
    /* 释放控制连接明文缓冲 */
    if (cl->ctl.plain) {
        evbuffer_free(cl->ctl.plain);
        cl->ctl.plain = NULL;
    }
    /* 释放 yamux 会话 */
    if (cl->session) {
        yamux_session_free(cl->session);
        cl->session = NULL;
    }
    /* 直连模式下的控制连接 bufferevent */
    if (!cl->ctl.use_yamux && cl->ctl.bev) {
        bufferevent_free(cl->ctl.bev);
    }
    memset(&cl->ctl, 0, sizeof(cl->ctl));
    cl->logged_in = 0;
    cl->run_id[0] = '\0';
}

/* 安排断线重连（固定间隔） */
static void schedule_reconnect(struct frp_client *cl)
{
    /* 连接已失效：先停心跳，避免在重连窗口内向已释放的连接写 Ping */
    cl->logged_in = 0;
    if (cl->stopping || !cl->reconnect_ev) return;
    struct timeval tv = { RECONNECT_INTERVAL_SEC, 0 };
    log_info("%d 秒后尝试重连...", RECONNECT_INTERVAL_SEC);
    evtimer_add(cl->reconnect_ev, &tv);
}

/*
 * 应用层心跳定时器（heartbeat_interval>0 时启用，默认 tcpMux 开启时为 -1 不启用）：
 *   - 每 heartbeat_interval 秒向服务器发送一次 Ping；
 *   - 按 heartbeat_timeout 校验距上次收到 Pong 的时间，超时则断开重连。
 * 对齐 Go frpc client/control.go 的 heartbeatWorker。
 */
static void ctl_heartbeat_cb(int fd, short what, void *ctx)
{
    (void)fd;
    (void)what;
    struct frp_client *cl = ctx;
    if (cl->stopping) return;

    time_t now = time(NULL);

    if (cl->logged_in) {
        if (cl->cfg->heartbeat_timeout > 0 && cl->last_pong > 0 &&
            (long)(now - cl->last_pong) > cl->cfg->heartbeat_timeout) {
            log_warn("心跳超时：%ld 秒未收到服务器 Pong，主动断开并重连",
                     (long)(now - cl->last_pong));
            client_reset(cl);
            schedule_reconnect(cl);
        } else if (cl->cfg->heartbeat_interval > 0 &&
                   (long)(now - cl->last_ping) >= cl->cfg->heartbeat_interval) {
            char *pj = ping_msg_build(cl->cfg->token, (int64_t)now, cl->cfg->auth_ping);
            if (pj) {
                conn_write_msg(&cl->ctl, FRP_MSG_PING, pj);
                free(pj);
            }
            cl->last_ping = now;
            log_debug("已发送心跳 Ping");
        }
    }

    struct timeval tv = { HEARTBEAT_TICK_SEC, 0 };
    evtimer_add(cl->heartbeat_ev, &tv);
}

/* 重连定时器回调 */
static void reconnect_cb(int fd, short what, void *ctx)
{
    (void)fd;
    (void)what;
    struct frp_client *cl = ctx;
    if (cl->stopping) return;

    char hp[300];
    frp_format_hostport(hp, sizeof(hp), cl->cfg->server_addr, cl->cfg->server_port);
    log_info("正在重新连接服务器 %s ...", hp);
    client_reset(cl);

    if (cl->cfg->tcp_mux) {
        cl->session = yamux_client(cl->base, cl->cfg->server_addr, cl->cfg->server_port);
        if (!cl->session) {
            log_error("重连失败");
            schedule_reconnect(cl);
            return;
        }
        cl->session->on_connect = on_session_connect;
        cl->session->on_close = on_session_close;
        cl->session->ctx = cl;
    } else {
        if (ctl_connect(cl) != 0) {
            log_error("重连失败");
            schedule_reconnect(cl);
            return;
        }
    }
}

/* yamux 会话断开回调，触发重连 */
static void on_session_close(struct yamux_session *s, void *ctx)
{
    (void)s;
    struct frp_client *cl = ctx;
    log_warn("与服务器连接已断开，准备重连");
    schedule_reconnect(cl);
}

static void tunnel_free(struct tunnel *t)
{
    /* 从全局链表移除 */
    if (t->px && t->px->client) {
        struct frp_client *cl = t->px->client;
        struct tunnel **pp = &cl->tunnels;
        while (*pp) {
            if (*pp == t) {
                *pp = t->next;
                break;
            }
            pp = &(*pp)->next;
        }
    }

    if (t->work.use_yamux) {
        /* 先解除 yamux 流的回调，避免 free(t) 后对端 FIN 触发悬空访问 */
        if (t->work.ys) {
            t->work.ys->on_data = NULL;
            t->work.ys->on_close = NULL;
            t->work.ys->on_established = NULL;
            t->work.ys->ctx = NULL;
            yamux_stream_close(t->work.ys);
            t->work.ys = NULL;
        }
    } else if (t->work.bev) {
        bufferevent_free(t->work.bev);
        t->work.bev = NULL;
    }
    if (t->local_bev) {
        bufferevent_free(t->local_bev);
        t->local_bev = NULL;
    }
    if (t->pending) evbuffer_free(t->pending);
    if (t->udp_ev) event_free(t->udp_ev);
    if (t->udp_ping_ev) event_free(t->udp_ping_ev);
    if (t->udp_fd > 0) close(t->udp_fd);
    if (t->work.plain) evbuffer_free(t->work.plain);
    free(t);
}

static void local_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    struct tunnel *t = ctx;
    if (what & BEV_EVENT_CONNECTED) {
        t->started = 1;
        /* 发送 Proxy Protocol v2 头（若启用） */
        if (t->pp_enabled) {
            uint8_t pp[52];
            int n = proxyproto_v2_build(0, t->pp_src_ip, t->pp_src_port,
                                        t->pp_dst_ip, t->pp_dst_port, pp, sizeof(pp));
            if (n > 0) {
                bufferevent_write(bev, pp, n);
            }
            t->pp_enabled = 0;
        }
        if (t->pending && evbuffer_get_length(t->pending) > 0) {
            bufferevent_write_buffer(bev, t->pending);
        }
        return;
    }
    if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        log_debug("本地连接断开，关闭隧道");
        bufferevent_free(bev);
        t->local_bev = NULL;
        tunnel_free(t);
    }
}

/* ---- work 连接：yamux 模式 ---- */

static void on_work_stream_data(struct yamux_stream *ys, void *ctx)
{
    (void)ys;
    struct frp_conn *c = ctx;
    conn_process_input(c);
}

static void on_work_stream_close(struct yamux_stream *ys, void *ctx)
{
    (void)ys;
    struct frp_conn *c = ctx;
    struct tunnel *t = c->ctx;
    log_debug("工作流关闭");
    tunnel_free(t);
}

/* ---- work 连接：直连模式 ---- */

static void work_read_cb(struct bufferevent *bev, void *ctx)
{
    (void)bev;
    struct tunnel *t = ctx;
    conn_process_input(&t->work);
}

static void work_event_cb(struct bufferevent *bev, short what, void *ctx)
{
    struct tunnel *t = ctx;
    if (what & BEV_EVENT_CONNECTED) {
        struct frp_client *cl = t->px->client;
        char *json = new_work_conn_msg_build(cl->run_id, cl->cfg->token,
                                             (int64_t)time(NULL), cl->cfg->auth_new_work_conn);
        if (json) {
            conn_write_msg(&t->work, FRP_MSG_NEW_WORK_CONN, json);
            free(json);
        }
    } else if (what & (BEV_EVENT_ERROR | BEV_EVENT_EOF)) {
        log_debug("工作连接断开");
        bufferevent_free(bev);
        t->work.bev = NULL;
        tunnel_free(t);
    }
}

/* 建立 work 连接（由 ReqWorkConn 触发） */
static int work_connect(struct frp_client *cl)
{
    struct tunnel *t = calloc(1, sizeof(*t));
    if (!t) return -1;

    t->px = &cl->proxies[0];

    /* 加入全局隧道链表 */
    t->next = cl->tunnels;
    cl->tunnels = t;

    memset(&t->work, 0, sizeof(t->work));
    t->work.frame_mode = 1;
    t->work.on_frame = work_on_frame;
    t->work.on_error = work_on_error;
    t->work.ctx = t;
    t->work.plain = evbuffer_new();

    if (cl->cfg->tcp_mux) {
        /* yamux 模式：打开新流 */
        struct yamux_stream *ys = yamux_open_stream(cl->session);
        if (!ys) {
            tunnel_free(t);
            return -1;
        }
        t->work.use_yamux = 1;
        t->work.ys = ys;
        ys->ctx = &t->work;
        ys->on_data = on_work_stream_data;
        ys->on_close = on_work_stream_close;

        /* 立即发 NewWorkConn（yamux 客户端发 SYN 后不等待 ACK） */
        char *json = new_work_conn_msg_build(cl->run_id, cl->cfg->token,
                                             (int64_t)time(NULL), cl->cfg->auth_new_work_conn);
        if (json) {
            conn_write_msg(&t->work, FRP_MSG_NEW_WORK_CONN, json);
            free(json);
        }
    } else {
        /* 直连模式：独立 TCP */
        struct bufferevent *bev = bev_connect(cl->base, cl->cfg->server_addr, cl->cfg->server_port);
        if (!bev) {
            log_error("建立工作连接失败");
            tunnel_free(t);
            return -1;
        }
        t->work.bev = bev;
        bufferevent_setcb(bev, work_read_cb, NULL, work_event_cb, t);
        bufferevent_enable(bev, EV_READ | EV_WRITE);
    }

    log_debug("已建立工作连接");
    return 0;
}

/* ---- 主循环 ---- */

int client_run(struct minifrpc_config *cfg)
{
    struct frp_client cl;
    memset(&cl, 0, sizeof(cl));
    cl.cfg = cfg;
    cl.base = event_base_new();
    if (!cl.base) {
        log_error("初始化事件循环失败");
        return -1;
    }

    /* 信号处理：Ctrl+C / kill 优雅退出 */
    struct event *sigint = evsignal_new(cl.base, SIGINT, sigint_cb, &cl);
    struct event *sigterm = evsignal_new(cl.base, SIGTERM, sigint_cb, &cl);
    if (sigint) evsignal_add(sigint, NULL);
    if (sigterm) evsignal_add(sigterm, NULL);
    log_debug("信号处理注册: sigint=%p sigterm=%p", (void *)sigint, (void *)sigterm);

    cl.proxy_count = cfg->proxy_count;
    cl.proxies = calloc((size_t)cfg->proxy_count, sizeof(struct proxy));
    if (!cl.proxies) {
        log_error("内存分配失败");
        event_base_free(cl.base);
        return -1;
    }
    for (int i = 0; i < cfg->proxy_count; i++) {
        cl.proxies[i].cfg = &cfg->proxies[i];
        cl.proxies[i].client = &cl;
    }

    /* 断线重连定时器 */
    cl.reconnect_ev = evtimer_new(cl.base, reconnect_cb, &cl);

    /* 应用层心跳定时器：heartbeat_interval>0 时启用（tcpMux 开启且未显式配置时默认 -1） */
    if (cfg->heartbeat_interval > 0) {
        cl.heartbeat_ev = evtimer_new(cl.base, ctl_heartbeat_cb, &cl);
        struct timeval hb_tv = { HEARTBEAT_TICK_SEC, 0 };
        evtimer_add(cl.heartbeat_ev, &hb_tv);
    }

    if (cfg->tcp_mux) {
        cl.session = yamux_client(cl.base, cfg->server_addr, cfg->server_port);
        if (!cl.session) {
            char hp[300];
            frp_format_hostport(hp, sizeof(hp), cfg->server_addr, cfg->server_port);
            log_error("无法连接服务器 %s", hp);
            free(cl.proxies);
            event_base_free(cl.base);
            return -1;
        }
        cl.session->on_connect = on_session_connect;
        cl.session->on_close = on_session_close;
        cl.session->ctx = &cl;
    } else {
        if (ctl_connect(&cl) != 0) {
            free(cl.proxies);
            event_base_free(cl.base);
            return -1;
        }
    }

    log_info("开始事件循环");
    event_base_dispatch(cl.base);
    log_info("事件循环结束");

    if (cl.ctl.plain) evbuffer_free(cl.ctl.plain);
    /* 清理所有活跃隧道 */
    while (cl.tunnels) {
        tunnel_free(cl.tunnels);
    }
    if (cl.session) yamux_session_free(cl.session);
    if (cl.reconnect_ev) event_free(cl.reconnect_ev);
    if (cl.heartbeat_ev) event_free(cl.heartbeat_ev);
    if (sigint) event_free(sigint);
    if (sigterm) event_free(sigterm);
    free(cl.proxies);
    event_base_free(cl.base);
    return 0;
}
