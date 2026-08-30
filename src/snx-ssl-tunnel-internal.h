/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_SSL_TUNNEL_INTERNAL_H
#define SNX_SSL_TUNNEL_INTERNAL_H

#include "snx-sexpr.h"
#include "snx-ssl-tunnel.h"

gboolean snx_ssl_parse_hello_reply(const SnxSexpr *expr, SnxSslHelloReply *out_reply, GError **error);

#endif
