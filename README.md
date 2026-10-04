<div align="center">

# minifrpc

**纯 C 极简 frpc 客户端 · 兼容 Go frp 0.71.0 · 嵌入式 musl 静态编译**

[![测试](https://github.com/lmq8267/minifrpc/actions/workflows/test.yml/badge.svg)](https://github.com/lmq8267/minifrpc/actions/workflows/test.yml)
[![Release](https://github.com/lmq8267/minifrpc/actions/workflows/release.yml/badge.svg)](https://github.com/lmq8267/minifrpc/actions/workflows/release.yml)
[![版本](https://img.shields.io/github/v/release/lmq8267/minifrpc?color=blue)](https://github.com/lmq8267/minifrpc/releases)
[![下载次数](https://img.shields.io/github/downloads/lmq8267/minifrpc/total?color=brightgreen)](https://github.com/lmq8267/minifrpc/releases)
[![反馈](https://img.shields.io/github/issues/lmq8267/minifrpc)](https://github.com/lmq8267/minifrpc/issues)
[![AskDeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/lmq8267/minifrpc)

</div>

---

## 简介

`minifrpc` 是一个用**纯 C** 编写的 frp 客户端（frpc），可直接连接**官方 Go 版 frps**（0.71.0）。
专为嵌入式设备设计：依赖少、体积小、能用 `musl-gcc` 交叉编译为**完全静态的单文件**，无需任何运行时依赖。

- 协议：frp `v1` wire 协议（兼容默认开启的 `tcpMux` / yamux）
- 功能：**TCP 代理、UDP 代理、Proxy Protocol v2**、中文日志
- 体积：静态编译 + strip 后约 **250KB**（对比同类型的 [xfrpc](https://github.com/lmq8267/xfrpc) 静态大小约 8MB）

## 特性

| 特性 | 说明 |
|------|------|
| 纯 C 实现 | 无 C++、无模板、无运行时框架 |
| 依赖本地编译 | json-c / libevent / tomlc17 源码置于 `vendor/`，`make` 一键编译，**不联网** |
| 完全静态 | musl 静态链接，单文件部署，无动态库依赖 |
| 兼容 Go frps | 支持 v1 协议与 yamux（tcpMux）多路复用 |
| TCP / UDP 代理 | 完整的 remote_port 转发 |
| Proxy Protocol v2 | 向本地服务传递真实客户端 IP（TCP/UDP 均支持） |
| 高并发 | epoll + libevent reactor，单线程事件驱动 |
| 中文日志 | 日志中文输出，时间戳为**北京时区**（Asia/Shanghai） |
| 明确报错 | 遇到不支持的功能（如 HTTP/TLS/加密）时输出中文错误并退出，不静默忽略 |
| 优雅退出 | 处理 `SIGINT` / `SIGTERM`，退出前清理全部连接 |

## 体积与性能

静态编译产物约 **250KB**。

压测（本地 frps，单核）参考数据：

| 场景 | 规模 | 结果 |
|------|------|------|
| TCP 转发 | 200 并发 × 10 次 = 2000 连接 | 成功 2000 / 失败 0（约 411 次/秒） |
| HTTP（经 TCP 转发承载） | 500 并发请求 | 成功 500 / 失败 0 |
| UDP 转发 | 300 并发 | 成功 300 / 失败 0 |
| Proxy Protocol v2 | 30 并发 | 成功 30 / 失败 0 |

进程常驻内存约 2MB，空闲 CPU 占用接近 0。

## 目录结构

```
minifrpc/
├── Makefile                    # 一键编译（含本地依赖编译 / 静态链接 / strip）
├── README.md                   # 本文件
├── example/
│   └── frpc.toml               # 配置示例
├── src/                        # 全部源码
│   ├── main.c                  # 入口：命令行解析、加载配置、启动
│   ├── config.c / config.h     # frp TOML 配置解析（不支持项报错）
│   ├── client.c / client.h     # 客户端核心：登录、注册代理、隧道、UDP、信号
│   ├── frp_msg.c / frp_msg.h   # v1 消息帧编解码（登录/注册/工作连接/UDP 包）
│   ├── yamux.c / yamux.h       # yamux 多路复用（tcpMux）
│   ├── proxyproto.c / .h       # Proxy Protocol v2 头构造
│   ├── base64.c / base64.h     # base64 编解码（UDP 数据用）
│   ├── log.c / log.h           # 中文日志（北京时区、级别、文件/控制台）
│   └── crypto/
│       ├── md5.c / md5.h       # MD5（privilege_key 计算）
│       ├── sha1.c / sha1.h     # SHA-1
│       ├── kdf.c / kdf.h       # HMAC-SHA1 + PBKDF2（控制通道密钥派生）
│       └── aes.c / aes.h       # AES-128 + CFB-128（控制通道加密）
├── vendor/                     # 第三方依赖源码（本地编译，不联网）
│   ├── json-c/                 # JSON 解析（MIT）
│   ├── libevent/               # 事件循环（BSD）
│   └── tomlc17/                # TOML 解析（MIT，单文件）
├── test/
│   └── crypto_test.c           # 加密算法自测（标准测试向量）
└── .github/workflows/
    ├── test.yml                # push 触发：动态/静态矩阵编译 + 摘要
    └── release.yml             # push/手动触发：多架构交叉编译 + 发布 Release
```

## 源码文件说明

**入口与配置**

| 文件 | 作用 |
|------|------|
| `src/main.c` | 命令行解析（`-c` / `-v` / `-h`）、加载配置、初始化日志、启动客户端主循环 |
| `src/config.c` `config.h` | 用 `tomlc17` 解析 frp 原生 TOML 配置；映射到 `struct minifrpc_config`；遇到不支持的功能时报中文错误并退出 |

**协议与数据面**

| 文件 | 作用 |
|------|------|
| `src/frp_msg.c` `frp_msg.h` | frp v1 消息帧（`1字节type + 8字节大端长度 + JSON`）的编解码；Login / NewProxy / NewWorkConn / StartWorkConn / UDPPacket 等消息结构；`privilege_key` 计算 |
| `src/client.c` `client.h` | 客户端核心：控制连接登录、代理注册、心跳、工作连接与隧道建立、TCP/UDP 数据转发、Proxy Protocol v2 注入、信号处理与退出清理 |
| `src/yamux.c` `yamux.h` | yamux 客户端协议（帧、流、窗口流控、keepalive），实现 tcpMux 多路复用 |
| `src/proxyproto.c` `proxyproto.h` | 构造 HAProxy PROXY protocol v2 头（IPv4/IPv6、TCP/UDP） |
| `src/base64.c` `base64.h` | 标准 base64 编解码，用于 UDP 包内容的封包/解包 |

**支撑模块**

| 文件 | 作用 |
|------|------|
| `src/log.c` `log.h` | 中文日志，支持 trace/debug/info/warn/error 级别，时间戳为北京时区 |
| `src/crypto/md5.c` | MD5 摘要（RFC 1321），用于认证 key |
| `src/crypto/sha1.c` | SHA-1 摘要（FIPS 180-1），PBKDF2/HMAC 基础 |
| `src/crypto/kdf.c` | HMAC-SHA1（RFC 2104）与 PBKDF2（RFC 2898），派生控制通道 AES 密钥 |
| `src/crypto/aes.c` | AES-128 分组加密与 CFB-128 流模式（控制通道加解密） |
| `test/crypto_test.c` | 加密算法自测程序（RFC/FIPS 标准测试向量） |

## 编译

### 依赖

仅需一个 C 编译器、`make` 与 `cmake`（用于编译 vendor 依赖）。依赖库源码已随项目提供，**编译过程不联网**。

Ubuntu / Debian：

```bash
sudo apt-get install -y build-essential cmake musl-tools
```

### 本地编译（动态链接，便于调试）

```bash
make
# 产物：build/minifrpc
```

### 静态编译（musl，嵌入式交付）

```bash
make static
# 产物：build/minifrpc（完全静态，约 250KB）
```

### 交叉编译

```bash
make CC=aarch64-linux-musl-gcc STRIP=aarch64-linux-musl-strip
```

### Makefile 变量

| 变量 | 默认 | 说明 |
|------|------|------|
| `CC` | `gcc` | 指定编译器（含 `musl` 时自动静态链接 + 独立依赖目录） |
| `STRIP` | 空 | 为空时用链接器 `-s` 完成 strip；指定时用独立 strip 工具（如 `aarch64-linux-musl-strip`） |

> 说明：`make` / `make static` 会**先自动清理**上次的编译产物与依赖库（避免不同架构产物混用），再全量编译。

## 配置

`minifrpc` 解析**原生 frp TOML 配置**。示例（`example/frpc.toml`）：

```toml
# 用户标识（可选）
user = "s-00tnkgv5445sv"

# 认证 token
auth.token = "your-token-here"

# frps 服务器地址与端口
serverAddr = "frp.example.com"
serverPort = 7000

# 传输层（仅支持 tcp，TLS 需关闭）
transport.protocol = "tcp"
transport.tls.enable = false

# 日志
log.level = "info"
log.to = "console"

# TCP 代理
[[proxies]]
name = "tcp-test"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8080
remotePort = 18080

# UDP 代理
[[proxies]]
name = "udp-test"
type = "udp"
localIP = "127.0.0.1"
localPort = 8282
remotePort = 18282

# TCP 代理 + Proxy Protocol v2（向本地服务传递真实客户端 IP）
[[proxies]]
name = "tcp-pp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 8585
remotePort = 18585
transport.proxyProtocolVersion = "v2"
```

### 顶层字段

| 字段 | 默认 | 说明 |
|------|------|------|
| `serverAddr` | 必填 | frps 地址 |
| `serverPort` | `7000` | frps 端口 |
| `user` | 空 | 用户标识 |
| `auth.token` | 空 | 认证 token |
| `transport.protocol` | `tcp` | 仅支持 `tcp` |
| `transport.tls.enable` | `false` | 仅支持 `false` |
| `transport.tcpMux` | `true` | 是否使用 yamux 多路复用 |
| `transport.poolCount` | `1` | 工作连接池大小 |
| `transport.heartbeatInterval` | tcpMux 关时 `30` | 心跳间隔（秒） |
| `transport.heartbeatTimeout` | tcpMux 关时 `90` | 心跳超时（秒） |
| `log.level` | `info` | 日志级别：trace/debug/info/warn/error |
| `log.to` | `console` | 输出目标：`console` 或文件路径 |

### 代理字段（`[[proxies]]`）

| 字段 | 说明 |
|------|------|
| `name` | 代理名（唯一） |
| `type` | `tcp` 或 `udp` |
| `localIP` | 本地服务地址（默认 `127.0.0.1`） |
| `localPort` | 本地服务端口 |
| `remotePort` | frps 监听的公网端口 |
| `transport.proxyProtocolVersion` | 空 / `v2`（仅支持 v2） |

## 运行

```bash
# 指定配置文件
minifrpc -c /etc/frp/frpc.toml

# 使用程序同目录的 frpc.toml（默认）
minifrpc

# 后台运行
minifrpc -c /etc/frp/frpc.toml >/dev/null 2>&1 &
```

### 命令行参数

| 参数 | 说明 |
|------|------|
| `-c <文件>` | 指定配置文件；不指定时使用**程序同目录的 `frpc.toml`** |
| `-v`, `--version` | 显示版本号（日期 + git 短哈希） |
| `-h`, `--help` | 显示帮助信息 |

## 支持的代理类型

| 类型 | 状态 | 说明 |
|------|------|------|
| `tcp` | ✅ 支持 | TCP 端口转发 |
| `udp` | ✅ 支持 | UDP 端口转发 |
| Proxy Protocol `v2` | ✅ 支持 | TCP / UDP 均可向本地服务注入真实客户端 IP |

## 不支持的配置（遇到即报错退出）

以下功能**未实现**，配置中出现时会输出中文错误并终止，避免静默失效：

- 代理类型：`http` / `https` / `stcp` / `xtcp` / `sudp` / `tcpmux`
- 传输加密：`transport.tls.enable = true`
- `useEncryption` / `useCompression`（数据面加密与压缩）
- `bandwidthLimit`（限速）
- `transport.protocol` 非 `tcp`（如 `kcp` / `quic` / `websocket`）
- `auth.method` 非 `token`（如 `oidc`）

## 协议说明

- **消息帧**：`1 字节 type + 8 字节大端长度 + JSON 体`
- **认证**：`privilege_key = hex(md5(token + 十进制时间戳))`
- **控制通道加密**：登录成功后，控制通道使用 **AES-128-CFB**，密钥由 `PBKDF2-HMAC-SHA1(token, "frp", 64, 16)` 派生
- **多路复用**：默认启用 yamux（tcpMux），控制流与工作流复用同一条 TCP 连接

## 部署（GitHub Actions）

| 工作流 | 触发 | 说明 |
|--------|------|------|
| `.github/workflows/test.yml` | `push` | 动态（gcc）/ 静态（musl-gcc）矩阵编译，输出编译摘要到 Step Summary |
| `.github/workflows/release.yml` | `push` / 手动 | 多架构（aarch64 / x86_64 / x86-32 / armv7 / arm / mips 等）musl 交叉编译，发布 Release（含未 UPX 与 `_upx` 两个版本） |

## 第三方依赖

| 依赖 | 用途 | 许可证 |
|------|------|--------|
| [json-c](https://github.com/json-c/json-c) | JSON 解析 | MIT |
| [libevent](https://libevent.org/) | 事件循环 | BSD |
| [tomlc17](https://github.com/cktan/tomlc17) | TOML 解析 | MIT |

