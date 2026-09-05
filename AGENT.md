# AGENT.md — xfrpc 项目分析指南

本文件为 AI 代理（Agent）提供分析、修改和构建本项目的核心上下文。

## 1. 项目概述

**xfrpc** 是一个用 C 语言实现的 [frp](https://github.com/fatedier/frp) 客户端（内网穿透），专为资源受限设备设计，目标是比其他方案占用更少的 ROM/RAM 空间。

- **语言**: C (C11 风格，使用 `_GNU_SOURCE`)
- **平台**: Linux（重点适配 OpenWrt/musl 交叉编译）
- **兼容性**: 与 frps 服务端部分兼容（tcp/tcpmux/http/https/udp/stcp/xtcp/socks5 等，详见 README.md 兼容表；`use_encryption`、`use_compression`、p2p 尚未支持；**QUIC 不支持**——ngtcp2 无 mbedTLS crypto 后端）

## 2. 构建系统

### 2.1 依赖库

| 依赖 | 用途 |
|------|------|
| libevent（**≥ 2.2**） | 事件循环 + `bufferevent_mbedtls_*`（TLS 传输硬依赖；2.1.x 仅有 OpenSSL 后端，不可用） |
| json-c | 控制消息 JSON 解析 |
| zlib | 压缩 |
| mbedTLS（**3.6.x**） | 唯一 TLS/加密后端：TLS 传输（经 libevent event_mbedtls）+ crypto 层（PBKDF2/AES-128-CFB/MD5/CTR_DRBG） |
| 内置 vendor | `vendor/snappy/`（压缩）、`vendor/tomlc17/`（TOML 解析） |

> ngtcp2/QUIC 已移除：ngtcp2 仅提供 OpenSSL/GnuTLS/wolfSSL/Picotls crypto 后端，
> 无 mbedTLS 后端。`quic_client_transport.c` 保留桩函数（`quic_transport_available()`
> 恒返回 0），`quic_transport.c/h` 已删除。

### 2.2 构建命令

```bash
mkdir build && cd build
cmake ..            # mbedTLS 单后端，无 QUIC 选项
make
```

### 2.3 CMake 选项（CMakeLists.txt）

| 选项 | 默认 | 说明 |
|------|------|------|
| `-DDEBUG=ON` | OFF | `-g -O0` 并定义 `XFRPC_DEBUG` |
| `-DENABLE_SANITIZER=ON` | ON | Debug 模式下启用 ASan/LSan |

**关键编译约束**：
- `-Wall -Werror` 全局开启（CI 中用 `-Wno-error=array-bounds` 规避误报）
- `-Wno-stringop-truncation` 针对遗留 `strncpy` 代码
- TLS/加密后端架构：`ssl_compat.h` 为 mbedTLS 伞头文件并声明全局 RNG `xfrpc_random()`（实现在 `utils.c`，entropy + CTR_DRBG）；`tls.c` 负责 TLS 传输（libevent `bufferevent_mbedtls_*`），`crypto.c` 负责加密原语（PBKDF2/AES-128-CFB/MD5）
- libevent 必须 ≥ 2.2 且以 mbedTLS 后端构建（cmake：`-DEVENT__DISABLE_OPENSSL=ON -DEVENT__DISABLE_MBEDTLS=OFF`），链接 `event_mbedtls` 库

## 3. 代码架构

### 3.1 启动流程

```
main.c::main
  → commandline.c::parse_commandline   # 解析命令行（-c 配置文件路径等）
  → login.c::init_login                # 加载/校验配置
  → xfrpc.c::xfrpc_loop                # 主事件循环（libevent event_base）
```

### 3.2 核心模块（根目录平铺结构）

| 模块 | 文件 | 职责 |
|------|------|------|
| **主循环** | `xfrpc.c/h` | event_base 创建、信号处理、控制连接调度 |
| **控制连接** | `control.c/h` | 与 frps 的控制通道：login/心跳/新代理请求/工作连接分发 |
| **消息协议** | `msg.c/h` | frp 二进制消息协议（1 字节 type + 8 字节 length + body），消息类型见 `msg.h`（与 frp v0.10.0 对齐） |
| **登录认证** | `login.c/h` | 登录帧构造、token 校验 |
| **配置解析** | `config.c/h`、`ini.c/h`、`toml_parser.c/h` | 双格式配置（INI/TOML），`xfrpc_full.toml`、`xfrpc_min.ini` 为样例 |
| **代理框架** | `proxy.c/h` | 代理会话管理（`proxy_client` 结构，`client.h`）、工作连接生命周期 |
| **TCP 代理** | `proxy_tcp.c`、`tcp_redir.c` | TCP 转发（含本地重定向） |
| **UDP 代理** | `proxy_udp.c` | UDP 包转发（`TypeUDPPacket` 消息） |
| **HTTP 多路复用** | `tcpmux.c/h` | HTTP CONNECT 隧道复用（http/https 子域/自定义域名） |
| **XTCP P2P** | `xtcp_client.c`、`xtcp_visitor.c`、`nathole.c` | NAT 打洞 + P2P 访客 |
| **STCP 访客** | `visitor.c` | stcp/xtcp 访客端连接 |
| **QUIC** | `quic_client_transport.c/h`（恒编译，仅桩函数：`quic_transport_available()` 返回 0） | QUIC 传输占位（ngtcp2 已移除，`protocol=quic` 运行时报错退出） |
| **加密/流** | `crypto.c`、`crypto_stream.c`、`zip.c` | PBKDF2/AES-128-CFB（mbedTLS）、流加密、snappy 压缩、zip |
| **TLS 隧道** | `tls.c/h`、`ssl_compat.h` | TLS-over-TCP 传输（libevent ≥2.2 `bufferevent_mbedtls_*` + mbedTLS 3.6） |
| **辅助** | `utils.c`、`common.c`、`debug.c`、`health_check.c`、`oidc_auth.c`、`mongoose.c`（嵌入式 HTTP） | 工具函数、健康检查、OIDC 认证 |
| **SOCKS5/xdpi** | `client.c/h` | SOCKS5 代理状态机、协议 DPI 识别（MSTSC/RDP/VNC/SSH 等） |
| **插件** | `plugins/` | telnetd/httpd/instaloader/youtubedl 挂载插件 |

### 3.3 数据流要点

- 控制连接与工作连接分离：`control.c` 维持长连接收发 JSON 控制消息；`TypeReqWorkConn`/`TypeNewWorkConn` 触发 `proxy.c` 建立工作连接
- 所有网络 I/O 基于 **libevent bufferevent**，勿混用阻塞 socket
- uthash（`uthash.h`）广泛用于哈希表管理
- 代理客户端结构 `proxy_client`（`client.h`）是贯穿全局的核心数据结构

## 4. 测试

- `test/` 目录：
  - `test_*.c` — 单元测试（如 `test_fastpbkdf2.c` 使用 mbedTLS `mbedtls_pkcs5_pbkdf2_hmac`、`test_iod_proto.c`）
  - `test_*.ini` — 各代理类型（http/ssh/stcp/tcpmux/uds）的配置样例
  - `test_performance.sh` — 性能测试脚本
  - `e2e/` — 端到端测试：证书对（`certs/`）、frps 服务端配置（`configs/frps-*.toml`，覆盖 tcp/tls/mux）、Python 辅助脚本（`test_proxy.py`、`tcp_echo_server.py`）
- CI：`.github/workflows/linux.yml`（musl 静态交叉编译 + Release 发布）、`.circleci/config.yml`、`cicd/azure-pipelines-xfrpc.yml`

## 5. 代码规范

- 格式化：`.clang-format`（配置存在，提交前可执行 clang-format）
- 注释语言：遵循用户要求使用**详细中文注释**
- 命名：snake_case 函数/变量；结构体 `struct xxx` 配套 `xxx.h` 头文件守卫 `XFRPC_XXX_H`
- 新增代码必须通过 `-Wall -Werror`

## 6. 常见任务速查

| 任务 | 涉及文件 |
|------|----------|
| 新增代理类型 | `proxy.c`（注册）+ 新建 `proxy_xxx.c` + `msg.h` 消息类型 |
| 修改协议消息 | `msg.h`（enum）+ `msg.c`（编解码）|
| 新增配置项 | `config.c`（INI/TOML 双路径都要处理）+ `xfrpc_full.toml` 文档 |
| TLS 相关改动 | `tls.c`（TLS 传输，libevent `bufferevent_mbedtls_*`）与 `crypto.c`（加密原语，mbedTLS）；改动后分别验证 TLS 握手与加密流。mbedTLS 无系统 CA 信任库，CA bundle 路径在 `tls.c::tls_load_system_ca` 探测 |
| QUIC 相关 | 不支持：ngtcp2 无 mbedTLS 后端；勿重新引入 `quic_transport.*` 或 OpenSSL 依赖 |
| 交叉编译调试 | 参考 `.github/workflows/linux.yml` 的 sysroot 构建流程（zlib→mbedTLS→json-c→libevent 2.2） |

## 7. 分析注意事项

1. **平台差异**：代码假定 POSIX/Linux，Windows 下仅能做静态分析（如本仓库在 Windows 上分析时，无法本地运行 cmake 构建）
2. **TLS/加密后端为 mbedTLS 3.6.x 单栈**——`ssl_compat.h` 统一引入 mbedTLS 头并声明全局 RNG；TLS 传输经 libevent ≥2.2 的 `bufferevent_mbedtls_*`，加密原语直接用 mbedTLS API。勿引入 OpenSSL/wolfSSL/其他 TLS 库；API 签名以 mbedTLS 3.6 头文件为准（3.x 与 2.x 差异大，如 `mbedtls_pk_parse_key_file` 必须传 f_rng）
3. `mongoose.c`、`uthash.h`、`ini.c` 为第三方嵌入式库，通常无需修改（mongoose 内 `MG_TLS_OPENSSL` 分支为死代码，`MG_TLS` 默认 `MG_TLS_NONE` 不编译）
4. 消息协议必须与 frp 服务端保持二进制兼容，改动 `msg.c/h` 前先对照 frp 上游实现
