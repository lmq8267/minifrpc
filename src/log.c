/*
 * minifrpc —— 纯 C 极简 frpc 客户端
 * log.c —— 中文日志模块实现（北京时区）
 *
 * 特性：
 *   - 时间戳为北京时区（Asia/Shanghai）
 *   - log.to 指定文件时：自动创建父目录、写文件的同时也输出到控制台（tee）
 *   - 日志文件超过 LOG_FILE_MAX_SIZE 时自动轮转（当前文件重命名为 .1）
 */

#include "log.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>

/* 日志文件最大字节数，超过则轮转（.1 备份） */
#define LOG_FILE_MAX_SIZE (10 * 1024 * 1024)

static int g_level = LOG_INFO;   /* 当前日志级别，低于此级别的日志不输出 */
static FILE *g_fp = NULL;        /* 输出文件，NULL 表示仅控制台 */
static int g_own_fp = 0;         /* 是否由本模块打开的文件 */
static char g_path[512] = {0};   /* 日志文件路径（轮转用） */

/* 级别名称（中文展示用） */
static const char *level_name(int level)
{
    switch (level) {
    case LOG_TRACE: return "TRACE";
    case LOG_DEBUG: return "DEBUG";
    case LOG_INFO:  return "INFO";
    case LOG_WARN:  return "WARN";
    case LOG_ERROR: return "ERROR";
    default:        return "?";
    }
}

/* 解析级别字符串，失败返回 -1 */
static int parse_level(const char *s)
{
    if (!s || !*s) return LOG_INFO;
    if (strcmp(s, "trace") == 0) return LOG_TRACE;
    if (strcmp(s, "debug") == 0) return LOG_DEBUG;
    if (strcmp(s, "info") == 0)  return LOG_INFO;
    if (strcmp(s, "warn") == 0)  return LOG_WARN;
    if (strcmp(s, "error") == 0) return LOG_ERROR;
    return -1;
}

/* 逐级创建父目录（类似 mkdir -p），已存在则忽略 */
static void mkdir_parents(const char *path)
{
    char tmp[512];
    snprintf(tmp, sizeof(tmp), "%s", path);

    char *slash = strrchr(tmp, '/');
    if (!slash) return;          /* 无目录部分（当前目录） */
    *slash = '\0';               /* tmp 变为目录路径 */
    if (tmp[0] == '\0') return;  /* 形如 "/xxx" */

    for (char *p = tmp + 1; *p; p++) {
        if (*p == '/') {
            *p = '\0';
            mkdir(tmp, 0755);    /* 忽略错误（多为“已存在”） */
            *p = '/';
        }
    }
    mkdir(tmp, 0755);
}

/* 日志轮转：当前文件重命名为 .1（覆盖旧备份），再重开当前文件 */
static void log_rotate(void)
{
    if (!g_fp || g_path[0] == '\0') return;
    fclose(g_fp);
    g_fp = NULL;

    char bak[600];
    snprintf(bak, sizeof(bak), "%s.1", g_path);
    remove(bak);                 /* 删除旧备份 */
    rename(g_path, bak);         /* 当前 -> .1 */

    g_fp = fopen(g_path, "a");   /* 重开空文件 */
    if (!g_fp) {
        g_own_fp = 0;
    }
}

int log_init(const char *level_str, const char *to)
{
    /* 设置北京时区 */
    setenv("TZ", "Asia/Shanghai", 1);
    tzset();

    int lv = parse_level(level_str);
    if (lv < 0) {
        fprintf(stderr, "[日志] 未知的日志级别: %s\n", level_str ? level_str : "");
        return -1;
    }
    g_level = lv;

    if (to && *to && strcmp(to, "console") != 0) {
        mkdir_parents(to);       /* 自动创建父目录 */
        g_fp = fopen(to, "a");
        if (!g_fp) {
            fprintf(stderr, "[日志] 无法打开日志文件: %s，回退到仅控制台输出\n", to);
            return -1;
        }
        g_own_fp = 1;
        snprintf(g_path, sizeof(g_path), "%s", to);
    }
    return 0;
}

void log_close(void)
{
    if (g_own_fp && g_fp) {
        fclose(g_fp);
    }
    g_fp = NULL;
    g_own_fp = 0;
    g_path[0] = '\0';
}

void log_write(int level, const char *fmt, ...)
{
    if (level < g_level) return;

    /* 时间戳：[YYYY-MM-DD HH:MM:SS] */
    time_t now = time(NULL);
    struct tm tm;
    localtime_r(&now, &tm);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", &tm);

    /* 格式化消息体 */
    char msg[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(msg, sizeof(msg), fmt, ap);
    va_end(ap);

    /* 始终输出到控制台（标准错误） */
    fprintf(stderr, "[%s] [%s] %s\n", ts, level_name(level), msg);
    fflush(stderr);

    /* 若配置了日志文件，同时写入（tee 效果），并按大小轮转 */
    if (g_fp) {
        struct stat st;
        if (g_path[0] && stat(g_path, &st) == 0 && st.st_size >= LOG_FILE_MAX_SIZE) {
            log_rotate();
        }
        if (g_fp) {
            fprintf(g_fp, "[%s] [%s] %s\n", ts, level_name(level), msg);
            fflush(g_fp);
        }
    }
}
