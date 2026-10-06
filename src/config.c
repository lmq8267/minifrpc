/*
 * minifrpc —— 纯 C 极简 frpc 客户端
 * config.c —— 配置解析（tomlc17 解析 frp 0.71 TOML 配置）
 *
 * 支持的功能：
 *   - TCP / UDP / HTTP / HTTPS 代理
 *   - Proxy Protocol v2
 * 解析到不支持的功能（TLS/加密/压缩/其他代理类型等）时输出中文错误并返回失败。
 */

#include "config.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "tomlc17.h"

/* 安全字符串复制，目标缓冲区 dst，最大 dst_sz 字节 */
static int copy_str(char *dst, size_t dst_sz, const char *src)
{
    if (!src) return -1;
    if (strlen(src) >= dst_sz) return -1;
    strcpy(dst, src);
    return 0;
}

/* 从表格中读取字符串，不存在或类型不符返回 def */
static void get_str(toml_datum_t tab, const char *key, char *out, size_t out_sz, const char *def)
{
    toml_datum_t d = toml_get(tab, key);
    if (d.type == TOML_STRING && copy_str(out, out_sz, d.u.s) == 0) {
        return;
    }
    if (def) copy_str(out, out_sz, def);
}

/* 从表格中读取整数，不存在或类型不符返回 def */
static long long get_int(toml_datum_t tab, const char *key, long long def)
{
    toml_datum_t d = toml_get(tab, key);
    if (d.type == TOML_INT64) return (long long)d.u.int64;
    return def;
}

/* 从表格中读取布尔，不存在或类型不符返回 def */
static int get_bool(toml_datum_t tab, const char *key, int def)
{
    toml_datum_t d = toml_get(tab, key);
    if (d.type == TOML_BOOLEAN) return d.u.boolean ? 1 : 0;
    return def;
}

/*
 * 读取 TOML 字符串数组并拼接为逗号分隔字符串（不存在则置空）。
 * 内容超出缓冲区时返回 -1，避免静默截断导致字段丢失后报出误导性错误。
 */
static int get_str_array_csv(toml_datum_t tab, const char *key, char *out, size_t out_sz)
{
    out[0] = '\0';
    toml_datum_t d = toml_get(tab, key);
    if (d.type != TOML_ARRAY) return 0;

    size_t used = 0;
    for (int i = 0; i < d.u.arr.size; i++) {
        toml_datum_t e = d.u.arr.elem[i];
        if (e.type != TOML_STRING || !e.u.s) continue;
        size_t sl = strlen(e.u.s);
        if (used + sl + 2 > out_sz) {
            log_error("配置项 %s 的第 %d 项过长（内容超过 %zu 字节），请缩短",
                      key, i + 1, out_sz);
            return -1;
        }
        if (used > 0) out[used++] = ',';
        memcpy(out + used, e.u.s, sl);
        used += sl;
        out[used] = '\0';
    }
    return 0;
}

/* 判断某个键是否存在（用于检测显式配置了不支持的功能） */
static int key_exists(toml_datum_t tab, const char *key)
{
    toml_datum_t d = toml_get(tab, key);
    return d.type != TOML_UNKNOWN;
}

/*
 * 解析单个 [[proxies]] 元素。
 * 返回 0 成功，-1 失败（不支持的功能）。
 */
static int parse_proxy(toml_datum_t elem, struct proxy_config *px)
{
    memset(px, 0, sizeof(*px));

    get_str(elem, "name", px->name, sizeof(px->name), "");
    get_str(elem, "type", px->type, sizeof(px->type), "");
    get_str(elem, "localIP", px->local_ip, sizeof(px->local_ip), "127.0.0.1");
    px->local_port = (int)get_int(elem, "localPort", 0);
    px->remote_port = (int)get_int(elem, "remotePort", 0);

    /* 类型检查：支持 tcp / udp / http / https */
    if (px->type[0] == '\0') {
        log_error("代理缺少 type 字段");
        return -1;
    }
    if (strcmp(px->type, "tcp") != 0 &&
        strcmp(px->type, "udp") != 0 &&
        strcmp(px->type, "http") != 0 &&
        strcmp(px->type, "https") != 0) {
        log_error("代理 [%s] 的类型 \"%s\" 暂不支持，当前仅支持 tcp/udp/http/https", px->name, px->type);
        return -1;
    }
    if (px->name[0] == '\0') {
        log_error("代理缺少 name 字段");
        return -1;
    }
    if (px->local_port <= 0 || px->local_port > 65535) {
        log_error("代理 [%s] 的 localPort 无效: %d", px->name, px->local_port);
        return -1;
    }

    /* 代理级不支持项：出现即报错，避免静默失效 */
    {
        static const char *unsup[] = {
            "enabled", "plugin", "loadBalancer", "healthCheck",
            "metadatas", "annotations", NULL
        };
        for (int i = 0; unsup[i]; i++) {
            if (key_exists(elem, unsup[i])) {
                log_error("代理 [%s] 的配置项 %s 暂不支持", px->name, unsup[i]);
                return -1;
            }
        }
    }

    if (strcmp(px->type, "http") == 0 || strcmp(px->type, "https") == 0) {
        /* ---- HTTP/HTTPS 代理：frps 侧 vhost 按域名路由（http 按 Host，https 按 TLS SNI），无需 remotePort ---- */
        get_str_array_csv(elem, "customDomains", px->custom_domains, sizeof(px->custom_domains));
        get_str(elem, "subdomain", px->subdomain, sizeof(px->subdomain), "");

        if (px->custom_domains[0] == '\0' && px->subdomain[0] == '\0') {
            log_error("代理 [%s] 为 %s 类型，必须配置 customDomains 或 subdomain",
                      px->name, px->type);
            return -1;
        }

        if (strcmp(px->type, "http") == 0) {
            get_str_array_csv(elem, "locations", px->locations, sizeof(px->locations));
            get_str(elem, "httpUser", px->http_user, sizeof(px->http_user), "");
            get_str(elem, "httpPassword", px->http_password, sizeof(px->http_password), "");
            get_str(elem, "hostHeaderRewrite", px->host_header_rewrite,
                    sizeof(px->host_header_rewrite), "");

            /* 暂不支持的 http 字段：出现即报错，避免静默失效 */
            if (key_exists(elem, "requestHeaders")) {
                log_error("代理 [%s] 的 requestHeaders（请求头改写）暂不支持", px->name);
                return -1;
            }
            if (key_exists(elem, "responseHeaders")) {
                log_error("代理 [%s] 的 responseHeaders（响应头改写）暂不支持", px->name);
                return -1;
            }
            if (key_exists(elem, "routeByHTTPUser")) {
                log_error("代理 [%s] 的 routeByHTTPUser 暂不支持", px->name);
                return -1;
            }
        } else {
            /* https 代理仅按域名路由，不支持 http 专有字段 */
            if (key_exists(elem, "locations") || key_exists(elem, "httpUser") ||
                key_exists(elem, "httpPassword") || key_exists(elem, "hostHeaderRewrite") ||
                key_exists(elem, "requestHeaders") || key_exists(elem, "responseHeaders") ||
                key_exists(elem, "routeByHTTPUser")) {
                log_error("代理 [%s] 为 https 类型，不支持 http 专有字段"
                          "（locations/httpUser/httpPassword/hostHeaderRewrite 等）", px->name);
                return -1;
            }
        }
    } else {
        /* ---- tcp / udp：需要 remotePort ---- */
        if (px->remote_port <= 0 || px->remote_port > 65535) {
            log_error("代理 [%s] 的 remotePort 无效: %d", px->name, px->remote_port);
            return -1;
        }
    }

    /* transport 子表（可选） */
    toml_datum_t t = toml_get(elem, "transport");
    if (t.type == TOML_TABLE) {
        /* Proxy Protocol 版本 */
        get_str(t, "proxyProtocolVersion", px->proxy_protocol_version,
                sizeof(px->proxy_protocol_version), "");
        if (px->proxy_protocol_version[0] != '\0') {
            if (strcmp(px->proxy_protocol_version, "v2") != 0) {
                log_error("代理 [%s] 的 transport.proxyProtocolVersion=\"%s\" 暂不支持，仅支持 v2",
                          px->name, px->proxy_protocol_version);
                return -1;
            }
        }
        px->use_encryption = get_bool(t, "useEncryption", 0);
        px->use_compression = get_bool(t, "useCompression", 0);
        if (px->use_encryption) {
            log_error("代理 [%s] 启用了 useEncryption 加密，暂不支持", px->name);
            return -1;
        }
        if (px->use_compression) {
            log_error("代理 [%s] 启用了 useCompression 压缩，暂不支持", px->name);
            return -1;
        }
        if (key_exists(t, "bandwidthLimit")) {
            log_error("代理 [%s] 配置了 bandwidthLimit 限速，暂不支持", px->name);
            return -1;
        }
    }

    return 0;
}

int config_load(const char *cfg_path, struct minifrpc_config *cfg)
{
    toml_result_t res = toml_parse_file_ex(cfg_path);
    if (!res.ok) {
        log_error("配置文件解析失败: %s", res.errmsg);
        return -1;
    }
    toml_datum_t top = res.toptab;

    /* ---- 顶层基本项 ---- */
    get_str(top, "serverAddr", cfg->server_addr, sizeof(cfg->server_addr), "");
    cfg->server_port = (int)get_int(top, "serverPort", 7000);
    get_str(top, "user", cfg->user, sizeof(cfg->user), "");
    cfg->login_fail_exit = get_bool(top, "loginFailExit", 1);

    if (cfg->server_addr[0] == '\0') {
        log_error("配置缺少 serverAddr（frps 服务器地址）");
        toml_free(res);
        return -1;
    }

    /* 顶层不支持项：出现即报错，避免静默失效 */
    {
        static const char *unsup[] = { "start", "includes", NULL };
        for (int i = 0; unsup[i]; i++) {
            if (key_exists(top, unsup[i])) {
                log_error("配置项 %s 暂不支持（会改变代理筛选或配置加载行为）", unsup[i]);
                toml_free(res);
                return -1;
            }
        }
    }

    /* ---- 认证 [auth] ---- */
    toml_datum_t auth = toml_get(top, "auth");
    if (auth.type == TOML_TABLE) {
        char method[32];
        get_str(auth, "method", method, sizeof(method), "token");
        if (strcmp(method, "token") != 0) {
            log_error("认证方式 auth.method=\"%s\" 暂不支持，仅支持 token", method);
            toml_free(res);
            return -1;
        }
        get_str(auth, "token", cfg->token, sizeof(cfg->token), "");

        /* additionalScopes：可选，取值 "HeartBeats" / "NewWorkConns"（对齐 frp v1） */
        toml_datum_t scopes = toml_get(auth, "additionalScopes");
        if (scopes.type == TOML_ARRAY) {
            for (int i = 0; i < scopes.u.arr.size; i++) {
                toml_datum_t sc = scopes.u.arr.elem[i];
                if (sc.type != TOML_STRING) continue;
                if (strcmp(sc.u.s, "HeartBeats") == 0) {
                    cfg->auth_ping = 1;
                } else if (strcmp(sc.u.s, "NewWorkConns") == 0) {
                    cfg->auth_new_work_conn = 1;
                } else {
                    log_error("认证附加范围 auth.additionalScopes 含不支持的值 \"%s\"，"
                              "仅支持 HeartBeats / NewWorkConns", sc.u.s);
                    toml_free(res);
                    return -1;
                }
            }
        }
    }

    /* ---- 传输层 [transport] ---- */
    cfg->protocol[0] = '\0';
    cfg->tls_enable = 0;
    cfg->tcp_mux = 1;
    cfg->heartbeat_interval = -1;
    cfg->heartbeat_timeout = -1;
    cfg->pool_count = 1;

    toml_datum_t tr = toml_get(top, "transport");
    if (tr.type == TOML_TABLE) {
        /* transport 级不支持项：出现即报错，避免静默失效 */
        {
            static const char *unsup[] = {
                "proxyURL", "wireProtocol", "connectServerLocalIP", "udpPacketSize", NULL
            };
            for (int i = 0; unsup[i]; i++) {
                if (key_exists(tr, unsup[i])) {
                    log_error("transport.%s 暂不支持", unsup[i]);
                    toml_free(res);
                    return -1;
                }
            }
        }

        get_str(tr, "protocol", cfg->protocol, sizeof(cfg->protocol), "tcp");
        if (strcmp(cfg->protocol, "tcp") != 0) {
            log_error("传输协议 transport.protocol=\"%s\" 暂不支持，仅支持 tcp", cfg->protocol);
            toml_free(res);
            return -1;
        }

        /* TLS：仅支持关闭 */
        toml_datum_t tls = toml_get(tr, "tls");
        if (tls.type == TOML_TABLE) {
            cfg->tls_enable = get_bool(tls, "enable", 0);
            if (cfg->tls_enable) {
                log_error("启用了 TLS 加密（transport.tls.enable=true），暂不支持");
                toml_free(res);
                return -1;
            }
        }

        cfg->tcp_mux = get_bool(tr, "tcpMux", 1);
        cfg->pool_count = (int)get_int(tr, "poolCount", 1);

        /* 心跳：tcpMux 开启时默认禁用，关闭时默认 30/90 秒 */
        long long hb_i = get_int(tr, "heartbeatInterval", INT64_MIN);
        long long hb_t = get_int(tr, "heartbeatTimeout", INT64_MIN);
        if (hb_i == INT64_MIN) hb_i = cfg->tcp_mux ? -1 : 30;
        if (hb_t == INT64_MIN) hb_t = cfg->tcp_mux ? -1 : 90;
        cfg->heartbeat_interval = (int)hb_i;
        cfg->heartbeat_timeout = (int)hb_t;
    }

    /* ---- 日志 [log] ---- */
    toml_datum_t logtab = toml_get(top, "log");
    if (logtab.type == TOML_TABLE) {
        get_str(logtab, "level", cfg->log_level, sizeof(cfg->log_level), "info");
        get_str(logtab, "to", cfg->log_to, sizeof(cfg->log_to), "console");
    }

    /* ---- 代理列表 [[proxies]] ---- */
    toml_datum_t parr = toml_get(top, "proxies");
    if (parr.type == TOML_ARRAY && parr.u.arr.size > 0) {
        cfg->proxy_count = parr.u.arr.size;
        cfg->proxies = calloc((size_t)cfg->proxy_count, sizeof(struct proxy_config));
        if (!cfg->proxies) {
            log_error("内存分配失败");
            toml_free(res);
            return -1;
        }
        for (int i = 0; i < parr.u.arr.size; i++) {
            toml_datum_t elem = parr.u.arr.elem[i];
            if (elem.type != TOML_TABLE) {
                log_error("代理配置格式错误");
                free(cfg->proxies);
                cfg->proxies = NULL;
                cfg->proxy_count = 0;
                toml_free(res);
                return -1;
            }
            if (parse_proxy(elem, &cfg->proxies[i]) != 0) {
                free(cfg->proxies);
                cfg->proxies = NULL;
                cfg->proxy_count = 0;
                toml_free(res);
                return -1;
            }
        }
    }

    toml_free(res);

    if (cfg->proxy_count == 0) {
        log_error("配置中没有任何代理（[[proxies]]）");
        return -1;
    }

    return 0;
}

void config_free(struct minifrpc_config *cfg)
{
    if (cfg->proxies) {
        free(cfg->proxies);
        cfg->proxies = NULL;
    }
    cfg->proxy_count = 0;
}
