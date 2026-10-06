/*
 * minifrpc —— 纯 C 极简 frpc 客户端
 * main.c —— 程序入口：命令行参数解析、配置加载、启动
 *
 * 命令行对齐 frp：
 *   -c <配置文件>   指定配置文件（默认使用程序同目录的 frpc.toml）
 *   -v / --version  打印版本号（日期+git短哈希）
 *   -h / --help     打印帮助信息
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "client.h"
#include "config.h"
#include "log.h"

#ifndef VERSION
#define VERSION "unknown"
#endif

static void print_version(void)
{
    printf("%s\n", VERSION);
}

/* 打印帮助信息（首尾各留空行，含命令示例与后台运行示例） */
static void print_usage(const char *prog)
{
    printf("\n");
    printf("minifrpc —— 纯 C 极简 frpc 客户端（兼容 Go frp）\n");
    printf("\n");
    printf("用法:\n");
    printf("  %s [选项]\n", prog);
    printf("\n");
    printf("选项:\n");
    printf("  -c, -C, --conf <文件>  指定配置文件（TOML），不指定时用程序同目录 frpc.toml\n");
    printf("  -v, -V, --version      显示版本号\n");
    printf("  -h, -H, --help         显示本帮助信息\n");
    printf("\n");
    printf("示例:\n");
    printf("  %s -c /etc/frp/frpc.toml   # 使用指定配置文件启动\n", prog);
    printf("  %s                         # 使用程序同目录的 frpc.toml 启动\n", prog);
    printf("  %s -v                      # 显示版本号\n", prog);
    printf("\n");
    printf("后台运行:\n");
    printf("  %s -c /etc/frp/frpc.toml >/dev/null 2>&1 &\n", prog);
    printf("\n");
}

/* 计算默认配置文件路径：程序所在目录 + /frpc.toml */
static void default_config_path(const char *argv0, char *out, size_t out_sz)
{
    const char *slash = strrchr(argv0, '/');
    if (slash) {
        int dirlen = (int)(slash - argv0);
        snprintf(out, out_sz, "%.*s/frpc.toml", dirlen, argv0);
    } else {
        /* argv[0] 不含路径（经 PATH 调用），回退到当前目录 */
        snprintf(out, out_sz, "%s", "frpc.toml");
    }
}

int main(int argc, char **argv)
{
    const char *cfg_path = NULL;
    char default_cfg[1024];

    /* 解析命令行参数 */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "-H") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "-V") == 0 || strcmp(argv[i], "--version") == 0) {
            print_version();
            return 0;
        } else if (strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "-C") == 0 || strcmp(argv[i], "--conf") == 0) {
            if (i + 1 < argc) {
                cfg_path = argv[++i];
            } else {
                fprintf(stderr, "错误: -c 缺少配置文件路径\n");
                print_usage(argv[0]);
                return 1;
            }
        } else {
            fprintf(stderr, "错误: 未知参数 \"%s\"\n", argv[i]);
            print_usage(argv[0]);
            return 1;
        }
    }

    /* 未指定 -c 时，使用程序同目录的 frpc.toml */
    if (!cfg_path) {
        default_config_path(argv[0], default_cfg, sizeof(default_cfg));
        cfg_path = default_cfg;
    }

    /* 先用默认日志（info / 标准错误）输出加载过程中的错误 */
    log_init(NULL, NULL);

    /* 检查配置文件是否存在 */
    FILE *fp = fopen(cfg_path, "r");
    if (!fp) {
        log_error("配置文件不存在或无法打开: %s", cfg_path);
        log_error("请用 -c <文件> 指定配置文件，或 -h 查看帮助");
        log_close();
        return 1;
    }
    fclose(fp);

    /* 加载配置 */
    struct minifrpc_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    if (config_load(cfg_path, &cfg) != 0) {
        log_error("配置加载失败，程序退出");
        log_close();
        return 1;
    }

    /* 按配置重设日志级别与输出目标 */
    log_close();
    log_init(cfg.log_level, cfg.log_to);

    log_info("配置文件加载成功: %s", cfg_path);
    char hp[300];
    frp_format_hostport(hp, sizeof(hp), cfg.server_addr, cfg.server_port);
    log_info("服务器: %s", hp);
    log_info("用户: %s", cfg.user[0] ? cfg.user : "(无)");
    log_info("多路复用(tcpMux): %s", cfg.tcp_mux ? "开启" : "关闭");
    if (cfg.heartbeat_interval > 0) {
        log_info("应用层心跳: 开启（间隔 %d 秒，超时 %d 秒）",
                 cfg.heartbeat_interval, cfg.heartbeat_timeout);
    } else {
        log_info("应用层心跳: 关闭（由 tcpMux 保活）");
    }
    for (int i = 0; i < cfg.proxy_count; i++) {
        struct proxy_config *px = &cfg.proxies[i];
        if (strcmp(px->type, "http") == 0 || strcmp(px->type, "https") == 0) {
            log_info("代理 [%s] 类型=%s 本地=%s:%d 域名=%s%s%s",
                     px->name, px->type, px->local_ip, px->local_port,
                     px->custom_domains[0] ? px->custom_domains : "",
                     (px->custom_domains[0] && px->subdomain[0]) ? "," : "",
                     px->subdomain[0] ? px->subdomain : "");
        } else {
            log_info("代理 [%s] 类型=%s 本地=%s:%d 远程端口=%d Proxy协议=%s",
                     px->name, px->type, px->local_ip, px->local_port,
                     px->remote_port,
                     px->proxy_protocol_version[0] ? px->proxy_protocol_version : "未开启");
        }
    }

    log_info("启动客户端，按 Ctrl+C 退出");
    int ret = client_run(&cfg);

    config_free(&cfg);
    log_close();
    return ret;
}
