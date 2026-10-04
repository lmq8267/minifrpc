/*
 * minifrpc —— v1 消息帧与 frp 协议消息编解码实现（基于 json-c）
 */

#include "frp_msg.h"
#include "base64.h"
#include "crypto/md5.h"

#include <json-c/json.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* 客户端版本：由 Makefile 编译时注入（-DVERSION，与 -v 输出一致） */
#ifndef VERSION
#define VERSION "unknown"
#endif

/* 目标平台架构宏 */
#if defined(__x86_64__) || defined(_M_X64)
#define FRP_ARCH "amd64"
#elif defined(__aarch64__) || defined(_M_ARM64)
#define FRP_ARCH "arm64"
#elif defined(__i386__)
#define FRP_ARCH "386"
#elif defined(__arm__)
#define FRP_ARCH "arm"
#elif defined(__mipsel__)
#define FRP_ARCH "mipsel"
#elif defined(__mips__)
#define FRP_ARCH "mips"
#else
#define FRP_ARCH "unknown"
#endif

/* 安全复制 json-c 字符串到目标缓冲区 */
static void jstr_copy(char *dst, size_t dst_sz, json_object *obj)
{
    if (!obj || !json_object_is_type(obj, json_type_string)) {
        dst[0] = '\0';
        return;
    }
    const char *s = json_object_get_string(obj);
    if (!s) {
        dst[0] = '\0';
        return;
    }
    snprintf(dst, dst_sz, "%s", s);
}

/* 从 json 对象取字符串字段 */
static const char *jget_str(json_object *obj, const char *key)
{
    json_object *v = json_object_object_get(obj, key);
    if (v && json_object_is_type(v, json_type_string)) {
        return json_object_get_string(v);
    }
    return NULL;
}

/* 从 json 对象取整数字段 */
static int jget_int(json_object *obj, const char *key, int def)
{
    json_object *v = json_object_object_get(obj, key);
    if (v && json_object_is_type(v, json_type_int)) {
        return json_object_get_int(v);
    }
    return def;
}

/* ---- 认证 ---- */
void frp_auth_key(const char *token, int64_t timestamp, char out[33])
{
    char ts[32];
    snprintf(ts, sizeof(ts), "%lld", (long long)timestamp);

    size_t tl = strlen(token ? token : "");
    size_t sl = strlen(ts);
    uint8_t *buf = malloc(tl + sl);
    if (!buf) {
        out[0] = '\0';
        return;
    }
    memcpy(buf, token ? token : "", tl);
    memcpy(buf + tl, ts, sl);
    md5_hex(buf, tl + sl, out);
    free(buf);
}

/* ---- 帧编解码 ---- */
size_t frp_frame_encode(uint8_t type, const char *json, size_t json_len,
                        uint8_t *out, size_t out_cap)
{
    if (out_cap < 1 + 8 + json_len) return 0;
    out[0] = type;
    /* 8 字节大端 int64 长度 */
    uint64_t len = (uint64_t)json_len;
    for (int i = 0; i < 8; i++) {
        out[1 + i] = (uint8_t)(len >> (8 * (7 - i)));
    }
    memcpy(out + 9, json, json_len);
    return 9 + json_len;
}

/* ---- 消息构造 ---- */
char *login_msg_build(const struct minifrpc_config *cfg, const char *run_id,
                      int64_t timestamp)
{
    char hostname[128] = "unknown";
    gethostname(hostname, sizeof(hostname) - 1);

    char priv_key[33];
    frp_auth_key(cfg->token, timestamp, priv_key);

    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "version", json_object_new_string(VERSION));
    json_object_object_add(obj, "hostname", json_object_new_string(hostname));
    json_object_object_add(obj, "os", json_object_new_string("linux"));
    json_object_object_add(obj, "arch", json_object_new_string(FRP_ARCH));
    if (cfg->user[0]) {
        json_object_object_add(obj, "user", json_object_new_string(cfg->user));
    }
    json_object_object_add(obj, "privilege_key", json_object_new_string(priv_key));
    json_object_object_add(obj, "timestamp", json_object_new_int64(timestamp));
    if (run_id && run_id[0]) {
        json_object_object_add(obj, "run_id", json_object_new_string(run_id));
    }
    json_object_object_add(obj, "pool_count", json_object_new_int(cfg->pool_count));

    char *ret = strdup(json_object_to_json_string(obj));
    json_object_put(obj);
    return ret;
}

char *new_proxy_msg_build(const struct proxy_config *px)
{
    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "proxy_name", json_object_new_string(px->name));
    json_object_object_add(obj, "proxy_type", json_object_new_string(px->type));
    json_object_object_add(obj, "remote_port", json_object_new_int(px->remote_port));

    char *ret = strdup(json_object_to_json_string(obj));
    json_object_put(obj);
    return ret;
}

char *new_work_conn_msg_build(const char *run_id, const char *token,
                              int64_t timestamp, int with_auth)
{
    json_object *obj = json_object_new_object();
    if (run_id && run_id[0]) {
        json_object_object_add(obj, "run_id", json_object_new_string(run_id));
    }
    /* additionalScopes 含 NewWorkConns 时附带 timestamp + privilege_key */
    if (with_auth) {
        char priv_key[33];
        frp_auth_key(token, timestamp, priv_key);
        json_object_object_add(obj, "timestamp", json_object_new_int64(timestamp));
        json_object_object_add(obj, "privilege_key", json_object_new_string(priv_key));
    }

    char *ret = strdup(json_object_to_json_string(obj));
    json_object_put(obj);
    return ret;
}

char *ping_msg_build(const char *token, int64_t timestamp, int with_auth)
{
    json_object *obj = json_object_new_object();
    /* additionalScopes 含 HeartBeats 时附带 timestamp + privilege_key */
    if (with_auth) {
        char priv_key[33];
        frp_auth_key(token, timestamp, priv_key);
        json_object_object_add(obj, "timestamp", json_object_new_int64(timestamp));
        json_object_object_add(obj, "privilege_key", json_object_new_string(priv_key));
    }

    char *ret = strdup(json_object_to_json_string(obj));
    json_object_put(obj);
    return ret;
}

char *udp_packet_msg_build(const uint8_t *content, size_t len,
                           const char *raddr_ip, int raddr_port)
{
    /* content 编码为 base64 */
    size_t b64_len = base64_encode_len(len);
    char *b64 = malloc(b64_len);
    if (!b64) return NULL;
    base64_encode(content, len, b64);

    json_object *obj = json_object_new_object();
    json_object_object_add(obj, "c", json_object_new_string(b64));
    free(b64);

    json_object *r = json_object_new_object();
    json_object_object_add(r, "IP", json_object_new_string(raddr_ip));
    json_object_object_add(r, "Port", json_object_new_int(raddr_port));
    json_object_object_add(obj, "r", r);

    char *ret = strdup(json_object_to_json_string(obj));
    json_object_put(obj);
    return ret;
}

/* ---- 消息解析 ---- */
int login_resp_parse(const char *json, struct login_resp *out)
{
    memset(out, 0, sizeof(*out));
    json_object *obj = json_tokener_parse(json);
    if (!obj) return -1;

    jstr_copy(out->version, sizeof(out->version), json_object_object_get(obj, "version"));
    jstr_copy(out->run_id, sizeof(out->run_id), json_object_object_get(obj, "run_id"));
    jstr_copy(out->error, sizeof(out->error), json_object_object_get(obj, "error"));
    json_object_put(obj);
    return 0;
}

int new_proxy_resp_parse(const char *json, struct new_proxy_resp *out)
{
    memset(out, 0, sizeof(*out));
    json_object *obj = json_tokener_parse(json);
    if (!obj) return -1;

    jstr_copy(out->proxy_name, sizeof(out->proxy_name), json_object_object_get(obj, "proxy_name"));
    jstr_copy(out->remote_addr, sizeof(out->remote_addr), json_object_object_get(obj, "remote_addr"));
    jstr_copy(out->error, sizeof(out->error), json_object_object_get(obj, "error"));
    json_object_put(obj);
    return 0;
}

int pong_err_parse(const char *json, char *out, size_t out_sz)
{
    out[0] = '\0';
    json_object *obj = json_tokener_parse(json);
    if (!obj) return 0;

    const char *e = jget_str(obj, "error");
    int has = (e && e[0] != '\0');
    if (has) snprintf(out, out_sz, "%s", e);
    json_object_put(obj);
    return has;
}

int start_work_conn_parse(const char *json, struct start_work_conn *out)
{
    memset(out, 0, sizeof(*out));
    json_object *obj = json_tokener_parse(json);
    if (!obj) return -1;

    jstr_copy(out->proxy_name, sizeof(out->proxy_name), json_object_object_get(obj, "proxy_name"));
    jstr_copy(out->src_addr, sizeof(out->src_addr), json_object_object_get(obj, "src_addr"));
    jstr_copy(out->dst_addr, sizeof(out->dst_addr), json_object_object_get(obj, "dst_addr"));
    out->src_port = jget_int(obj, "src_port", 0);
    out->dst_port = jget_int(obj, "dst_port", 0);
    jstr_copy(out->error, sizeof(out->error), json_object_object_get(obj, "error"));
    json_object_put(obj);
    return 0;
}

int udp_packet_parse(const char *json, struct udp_packet *out)
{
    memset(out, 0, sizeof(*out));
    json_object *obj = json_tokener_parse(json);
    if (!obj) return -1;

    /* content：base64 字符串 */
    const char *c = jget_str(obj, "c");
    if (c) {
        size_t clen = strlen(c);
        out->content = malloc(base64_decode_len(c, clen) + 1);
        if (out->content) {
            int n = base64_decode(c, clen, out->content);
            if (n < 0) {
                free(out->content);
                out->content = NULL;
            } else {
                out->content_len = (size_t)n;
            }
        }
    }

    /* remote addr */
    json_object *r = json_object_object_get(obj, "r");
    if (r && json_object_is_type(r, json_type_object)) {
        jstr_copy(out->raddr_ip, sizeof(out->raddr_ip), json_object_object_get(r, "IP"));
        out->raddr_port = jget_int(r, "Port", 0);
    }
    json_object_put(obj);
    return 0;
}

void udp_packet_free(struct udp_packet *p)
{
    if (p->content) {
        free(p->content);
        p->content = NULL;
    }
    p->content_len = 0;
}
