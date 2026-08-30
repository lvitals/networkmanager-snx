/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_SSL_TUNNEL_H
#define SNX_SSL_TUNNEL_H

#include "snx-slim.h"

#include <gio/gio.h>
#include <glib.h>

/*
 * The SSL VPN data tunnel: a persistent TLS connection to the gateway's
 * TCPT port, carrying SLIM-framed packets (see snx-slim.h). This module
 * only handles the connection and the client_hello/hello_reply handshake;
 * the caller owns the packet-forwarding loop.
 */

typedef struct {
    guint32 from_be;
    guint32 to_be;
} SnxNetworkRange;

typedef struct {
    char *assigned_ip;             /* dotted-quad string, e.g. "10.1.2.3" */
    char *subnet_mask;              /* dotted-quad string, may be NULL if the gateway omitted it */
    guint authentication_timeout_seconds;
    guint keepalive_seconds;
    GPtrArray *dns_servers;         /* element-type char*, acquired from OM:dns_servers */
    GPtrArray *search_domains;      /* element-type char*, acquired from OM:dns_suffix */
    GPtrArray *ranges;              /* element-type SnxNetworkRange*, may be empty */
} SnxSslHelloReply;

void snx_ssl_hello_reply_clear(SnxSslHelloReply *reply);

typedef struct _SnxSslTunnel SnxSslTunnel;

/* Blocking: opens a TLS connection to server_name:tcpt_port and performs
 * the client_hello/hello_reply handshake using session_cookie (the CCC
 * auth response's active_key). Call from a worker thread, not the main
 * loop. On success, fills out_reply (still owned by the caller; clear it
 * with snx_ssl_hello_reply_clear() when done). */
SnxSslTunnel *snx_ssl_tunnel_connect(const char *server_name,
                                     guint16 tcpt_port,
                                     gboolean ignore_server_cert,
                                     const char *session_cookie,
                                     SnxSslHelloReply *out_reply,
                                     GError **error);

void snx_ssl_tunnel_free(SnxSslTunnel *tunnel);

/* Blocking. */
gboolean snx_ssl_tunnel_send_data(SnxSslTunnel *tunnel, const guint8 *data, gsize len, GError **error);
gboolean snx_ssl_tunnel_send_keepalive(SnxSslTunnel *tunnel, GError **error);

/* Blocking: reads and returns the next complete SLIM packet (Control or
 * Data). Transfer full. */
SnxSlimPacket *snx_ssl_tunnel_receive(SnxSslTunnel *tunnel, GError **error);

/* Closing the underlying connection unblocks a concurrent
 * snx_ssl_tunnel_receive() call in another thread with an error, so it can
 * be used to stop a receive loop from outside. */
void snx_ssl_tunnel_close(SnxSslTunnel *tunnel);

#endif
