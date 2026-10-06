/*
 * minifrpc —— 纯 C 极简 frpc 客户端
 * config.h —— 配置结构体与解析声明（对齐 frp 0.71 TOML 配置）
 */

#ifndef MINIFRPC_CONFIG_H
#define MINIFRPC_CONFIG_H

#include <stdint.h>

/* 单个代理配置（对应 [[proxies]] 数组元素） */
struct proxy_config {
    char name[128];                     /* 代理名 */
    char type[16];                      /* 代理类型，支持 tcp/udp/http/https */
    char local_ip[64];                  /* 本地服务 IP */
    int  local_port;                    /* 本地服务端口 */
    int  remote_port;                   /* frps 监听端口（tcp/udp） */
    char proxy_protocol_version[8];     /* 空 / v1 / v2 */
    int  use_encryption;                /* 是否启用传输加密（暂不支持） */
    int  use_compression;               /* 是否启用压缩（暂不支持） */

    /* HTTP/HTTPS 代理专有字段（经 frps 的 vhostHttp(s)Port 按域名路由） */
    char custom_domains[512];           /* 自定义域名，多个以逗号分隔 */
    char subdomain[128];                /* 子域名（与 frps 的 subDomainHost 拼接） */
    char locations[512];                /* URL 路径前缀，多个以逗号分隔（仅 http） */
    char http_user[128];                /* 访问认证用户名（Basic Auth，仅 http） */
    char http_password[128];            /* 访问认证密码（仅 http） */
    char host_header_rewrite[256];      /* 转发时重写的 Host 头（仅 http） */
};

/* 客户端全局配置（对应 TOML 顶层 + [transport]/[auth]/[log]） */
struct minifrpc_config {
    /* 服务器 */
    char server_addr[256];
    int  server_port;
    int  login_fail_exit;               /* 首次登录失败是否退出，默认 1（对齐 Go） */

    /* 认证 */
    char token[256];
    char user[128];
    int  auth_ping;                     /* additionalScopes 含 HeartBeats：Ping 携带鉴权 */
    int  auth_new_work_conn;            /* additionalScopes 含 NewWorkConns：NewWorkConn 携带鉴权 */

    /* 传输层 */
    char protocol[16];                  /* 仅支持 tcp */
    int  tls_enable;                    /* 仅支持 0 */
    int  tcp_mux;                       /* 默认 1 */
    int  heartbeat_interval;            /* 秒，-1 表示禁用 */
    int  heartbeat_timeout;             /* 秒，-1 表示禁用 */
    int  pool_count;                    /* 工作连接池大小，默认 1 */

    /* 日志 */
    char log_level[16];
    char log_to[128];

    /* 代理列表 */
    struct proxy_config *proxies;
    int  proxy_count;
};

/*
 * 解析 frp TOML 配置文件。
 * cfg_path: 配置文件路径
 * cfg:      输出配置结构体（调用者分配，需先 memset 为 0）
 * 返回 0 成功；-1 失败（配置语法错误或包含不支持的功能）。
 * 错误信息通过 log_error 输出（中文）。
 */
int config_load(const char *cfg_path, struct minifrpc_config *cfg);

/* 释放配置中动态分配的内存 */
void config_free(struct minifrpc_config *cfg);

#endif /* MINIFRPC_CONFIG_H */
