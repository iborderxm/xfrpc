// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * QUIC Client Transport —— QUIC 传输占位实现（stub）
 *
 * 说明：本项目 TLS/加密后端已全量切换为 mbedTLS 3.6.x，而 ngtcp2 不提供
 * mbedTLS 的 crypto 后端（仅支持 OpenSSL/GnuTLS/wolfSSL/Picotls），因此
 * QUIC 传输不再编译。本文件保留 quic_transport_available/quic_connect_to_server/
 * quic_open_work_stream 三个桩函数，供 control.c / xtcp_*.c 等调用点在
 * 运行时得到明确的“未编译 QUIC”反馈，避免 #ifdef 散落在业务代码中。
 */

#include "quic_client_transport.h"
#include "debug.h"

/* QUIC 传输是否可用：始终为 0（未编译 ngtcp2 后端） */
int quic_transport_available(void) { return 0; }

/* 发起 QUIC 连接：桩实现，直接报错返回失败 */
int quic_connect_to_server(struct event_base *b,
			   const char *a, int p,
			   quic_handshake_cb cb, void *cb_arg)
{
	(void)b; (void)a; (void)p; (void)cb; (void)cb_arg;
	debug(LOG_ERR, "QUIC not compiled in");
	return -1;
}

/* 打开工作流：桩实现，返回 NULL */
struct bufferevent *quic_open_work_stream(struct event_base *b)
{
	(void)b;
	debug(LOG_ERR, "QUIC not compiled in");
	return NULL;
}
