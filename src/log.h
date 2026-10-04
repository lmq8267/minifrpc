/*
 * minifrpc —— 纯 C 极简 frpc 客户端
 * log.h —— 中文日志模块（北京时区）
 *
 * 日志级别对齐 frp：trace < debug < info < warn < error
 * 时间戳使用北京时区（Asia/Shanghai，UTC+8）
 */

#ifndef MINIFRPC_LOG_H
#define MINIFRPC_LOG_H

#include <stdio.h>

/* 日志级别（值越小越详细） */
#define LOG_TRACE 0
#define LOG_DEBUG 1
#define LOG_INFO  2
#define LOG_WARN  3
#define LOG_ERROR 4

/*
 * 初始化日志模块。
 * level_str: 日志级别字符串（"trace"/"debug"/"info"/"warn"/"error"）
 * to:        输出目标，NULL 或 "console" 表示标准错误输出，否则为文件路径
 * 返回 0 成功，-1 失败。
 */
int log_init(const char *level_str, const char *to);

/* 关闭日志模块（关闭可能打开的文件） */
void log_close(void);

/* 日志输出主函数，一般不直接调用，请使用下面的宏 */
void log_write(int level, const char *fmt, ...)
#if defined(__GNUC__)
    __attribute__((format(printf, 2, 3)))
#endif
    ;

/* 便捷宏 */
#define log_trace(...) log_write(LOG_TRACE, __VA_ARGS__)
#define log_debug(...) log_write(LOG_DEBUG, __VA_ARGS__)
#define log_info(...)  log_write(LOG_INFO,  __VA_ARGS__)
#define log_warn(...)  log_write(LOG_WARN,  __VA_ARGS__)
#define log_error(...) log_write(LOG_ERROR, __VA_ARGS__)

#endif /* MINIFRPC_LOG_H */
