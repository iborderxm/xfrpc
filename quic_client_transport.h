// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * QUIC Client Transport —— QUIC 传输接口（当前为 stub 实现）
 *
 * 历史上 xfrpc 可通过 ngtcp2 经 QUIC(UDP) 连接 frps，并返回由
 * socketpair <-> QUIC stream 支撑的 libevent bufferevent，使 msg.c /
 * control.c / login.c 等业务代码无需感知传输差异。
 *
 * 现状：TLS/加密后端全量切换为 mbedTLS 3.6.x 后，ngtcp2 因无 mbedTLS
 * crypto 后端（仅支持 OpenSSL/GnuTLS/wolfSSL/Picotls）不再编译，
 * quic_client_transport.c 仅提供桩函数：quic_transport_available()
 * 恒返回 0，连接/开流调用返回失败并打印日志。
 */

#ifndef XFRPC_QUIC_CLIENT_TRANSPORT_H
#define XFRPC_QUIC_CLIENT_TRANSPORT_H

#include <event2/event.h>
#include <event2/bufferevent.h>

/**
 * @brief QUIC 握手完成（或失败）时的回调
 *
 * @param bev  成功时为 bufferevent，失败时为 NULL
 * @param arg  调用方提供的不透明指针
 */
typedef void (*quic_handshake_cb)(struct bufferevent *bev, void *arg);

/**
 * @brief 异步发起到 frps 的 QUIC 连接（桩实现：直接返回 -1）
 *
 * @param base         libevent base
 * @param server_addr  frps 主机名或 IP
 * @param port         frps QUIC 端口（quicBindPort）
 * @param cb           握手完成回调
 * @param arg          透传给回调的不透明指针
 * @return 0 表示握手已启动，-1 表示立即失败（stub 恒为 -1）
 */
int quic_connect_to_server(struct event_base *base,
			   const char *server_addr,
			   int port,
			   quic_handshake_cb cb,
			   void *arg);

/**
 * @brief 查询 QUIC 传输是否可用（ngtcp2 是否编译进来）
 * @return 1 可用，0 不可用（mbedTLS 构建恒为 0）
 */
int quic_transport_available(void);

/**
 * @brief 在既有 QUIC 连接上打开一条新的工作流（桩实现：返回 NULL）
 *
 * @param base  libevent base
 * @return bufferevent，失败返回 NULL
 */
struct bufferevent *quic_open_work_stream(struct event_base *base);

#endif /* XFRPC_QUIC_CLIENT_TRANSPORT_H */
