/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-ssl-tunnel.h"

#include "snx-errors.h"
#include "snx-ssl-tunnel-internal.h"
#include "snx-sexpr-writer.h"
#include "snx-sexpr.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>

struct _SnxSslTunnel {
    GSocketClient *client;
    GSocketConnection *conn;
    GByteArray *recv_buffer;
    /* snx_ssl_tunnel_send_data() (uplink thread) and
     * snx_ssl_tunnel_send_keepalive() (main-thread timer) can be called
     * concurrently; without this, two interleaved writes would corrupt the
     * SLIM framing on the wire. Receiving has only ever one caller
     * (the downlink thread), so it needs no lock. */
    GMutex write_lock;
};

void
snx_ssl_hello_reply_clear(SnxSslHelloReply *reply)
{
    g_clear_pointer(&reply->assigned_ip, g_free);
    g_clear_pointer(&reply->subnet_mask, g_free);
    g_clear_pointer(&reply->dns_servers, g_ptr_array_unref);
    g_clear_pointer(&reply->search_domains, g_ptr_array_unref);
    g_clear_pointer(&reply->ranges, g_ptr_array_unref);
    memset(reply, 0, sizeof(*reply));
}

static gboolean
accept_any_certificate(GTlsConnection *conn, GTlsCertificate *peer_cert, GTlsCertificateFlags errors,
                       gpointer user_data)
{
    (void) conn;
    (void) peer_cert;
    (void) errors;
    (void) user_data;
    return TRUE;
}

static void
on_socket_client_event(GSocketClient *client, GSocketClientEvent event, GSocketConnectable *connectable,
                       GIOStream *connection, gpointer user_data)
{
    gboolean ignore_cert = GPOINTER_TO_INT(user_data);

    (void) client;
    (void) connectable;

    if (event == G_SOCKET_CLIENT_TLS_HANDSHAKING && ignore_cert && G_IS_TLS_CONNECTION(connection))
        g_signal_connect(connection, "accept-certificate", G_CALLBACK(accept_any_certificate), NULL);
}

static char *
build_client_hello(const char *cookie)
{
    SnxWriter *root = snx_writer_new_object("client_hello");
    SnxWriter *office_mode = snx_writer_add_object(root, "OM", NULL);
    SnxWriter *optional = snx_writer_add_object(root, "optional", NULL);
    char *result;

    snx_writer_set_uint(root, "client_version", 2);
    snx_writer_set_uint(root, "protocol_version", 2);
    snx_writer_set_string(root, "cookie", cookie);

    snx_writer_set_string(office_mode, "ipaddr", "0.0.0.0");
    snx_writer_set_bool(office_mode, "keep_address", FALSE);

    snx_writer_set_string(optional, "client_type", "4");

    result = snx_writer_to_string(root);
    snx_writer_free(root);
    return result;
}

static gboolean
write_packet(GOutputStream *ostream, const SnxSlimPacket *packet, GError **error)
{
    g_autoptr(GBytes) encoded = snx_slim_encode(packet);
    gsize len;
    const guint8 *data = g_bytes_get_data(encoded, &len);

    return g_output_stream_write_all(ostream, data, len, NULL, NULL, error);
}

static SnxSlimPacket *
read_one_packet(GInputStream *istream, GByteArray *buf, GError **error)
{
    for (;;) {
        gsize consumed = 0;
        SnxSlimPacket *packet = snx_slim_decode(buf->data, buf->len, &consumed, error);
        guint8 chunk[4096];
        gssize n;

        if (packet != NULL) {
            g_byte_array_remove_range(buf, 0, (guint) consumed);
            return packet;
        }
        if (*error != NULL)
            return NULL;

        n = g_input_stream_read(istream, chunk, sizeof(chunk), NULL, error);
        if (n < 0)
            return NULL;
        if (n == 0) {
            g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "tunnel connection closed unexpectedly");
            return NULL;
        }
        g_byte_array_append(buf, chunk, (guint) n);
    }
}

static gboolean
parse_value_list(const SnxSexpr *list, GPtrArray *out_values)
{
    const char *single_value = snx_sexpr_value_string(list);

    if (single_value != NULL) {
        g_ptr_array_add(out_values, g_strdup(single_value));
        return TRUE;
    }

    for (guint i = 0; i < snx_sexpr_field_count(list); i++) {
        const char *value = snx_sexpr_value_string(snx_sexpr_field_value(list, i));

        if (value != NULL && *value != '\0')
            g_ptr_array_add(out_values, g_strdup(value));
    }

    return TRUE;
}

static gboolean
parse_delimited_string_list(const char *value, GPtrArray *out_values)
{
    g_auto(GStrv) parts = NULL;

    if (value == NULL)
        return TRUE;

    parts = g_strsplit_set(value, ",;", -1);
    for (guint i = 0; parts[i] != NULL; i++) {
        char *trimmed = g_strstrip(parts[i]);

        if (*trimmed != '\0')
            g_ptr_array_add(out_values, g_strdup(trimmed));
    }

    return TRUE;
}

static gboolean
parse_network_range_list(const SnxSexpr *list, GPtrArray *out_ranges)
{
    guint count = snx_sexpr_field_count(list);
    guint i;

    for (i = 0; i < count; i++) {
        const SnxSexpr *item = snx_sexpr_field_value(list, i);
        const char *from = snx_sexpr_get_string(item, "from");
        const char *to = snx_sexpr_get_string(item, "to");
        SnxNetworkRange *range;
        struct in_addr addr;

        if (from == NULL || to == NULL)
            continue;

        range = g_new0(SnxNetworkRange, 1);
        if (inet_pton(AF_INET, from, &addr) == 1)
            range->from_be = addr.s_addr;
        if (inet_pton(AF_INET, to, &addr) == 1)
            range->to_be = addr.s_addr;

        g_ptr_array_add(out_ranges, range);
    }

    return TRUE;
}

gboolean
snx_ssl_parse_hello_reply(const SnxSexpr *expr, SnxSslHelloReply *out_reply, GError **error)
{
    const char *ipaddr = snx_sexpr_get_string(expr, "OM:ipaddr");
    const char *subnet = snx_sexpr_get_string(expr, "optional:subnet");
    const char *auth_timeout = snx_sexpr_get_string(expr, "timeouts:authentication");
    const char *keepalive = snx_sexpr_get_string(expr, "timeouts:keepalive");
    const char *dns_suffix = snx_sexpr_get_string(expr, "OM:dns_suffix");
    const SnxSexpr *dns_servers = snx_sexpr_get(expr, "OM:dns_servers");
    const SnxSexpr *range_list = snx_sexpr_get(expr, "range");

    if (ipaddr == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "hello_reply is missing OM:ipaddr");
        return FALSE;
    }

    memset(out_reply, 0, sizeof(*out_reply));
    out_reply->assigned_ip = g_strdup(ipaddr);
    out_reply->subnet_mask = g_strdup(subnet);
    out_reply->authentication_timeout_seconds = auth_timeout != NULL ? (guint) g_ascii_strtoull(auth_timeout, NULL, 10) : 0;
    out_reply->keepalive_seconds = keepalive != NULL ? (guint) g_ascii_strtoull(keepalive, NULL, 10) : 0;
    out_reply->dns_servers = g_ptr_array_new_with_free_func(g_free);
    out_reply->search_domains = g_ptr_array_new_with_free_func(g_free);
    out_reply->ranges = g_ptr_array_new_with_free_func(g_free);

    if (dns_servers != NULL)
        parse_value_list(dns_servers, out_reply->dns_servers);
    parse_delimited_string_list(dns_suffix, out_reply->search_domains);

    if (range_list != NULL)
        parse_network_range_list(range_list, out_reply->ranges);

    return TRUE;
}

SnxSslTunnel *
snx_ssl_tunnel_connect(const char *server_name, guint16 tcpt_port, gboolean ignore_server_cert,
                       const char *session_cookie, SnxSslHelloReply *out_reply, GError **error)
{
    g_autoptr(GSocketClient) client = g_socket_client_new();
    GSocketConnection *conn;
    g_autofree char *hello_text = NULL;
    g_autoptr(SnxSlimPacket) hello_packet = NULL;
    SnxSlimPacket *reply_packet = NULL;
    SnxSexpr *reply_expr = NULL;
    SnxSslTunnel *tunnel;
    GOutputStream *ostream;
    GInputStream *istream;
    gboolean ok;

    g_socket_client_set_tls(client, TRUE);
    g_socket_client_set_timeout(client, 15);
    g_signal_connect(client, "event", G_CALLBACK(on_socket_client_event), GINT_TO_POINTER(ignore_server_cert));

    conn = g_socket_client_connect_to_host(client, server_name, tcpt_port, NULL, error);
    if (conn == NULL)
        return NULL;

    ostream = g_io_stream_get_output_stream(G_IO_STREAM(conn));
    istream = g_io_stream_get_input_stream(G_IO_STREAM(conn));

    hello_text = build_client_hello(session_cookie);
    hello_packet = snx_slim_packet_new_control(hello_text);
    if (!write_packet(ostream, hello_packet, error)) {
        g_object_unref(conn);
        return NULL;
    }

    tunnel = g_new0(SnxSslTunnel, 1);
    tunnel->client = g_steal_pointer(&client);
    tunnel->conn = conn;
    tunnel->recv_buffer = g_byte_array_new();
    g_mutex_init(&tunnel->write_lock);

    reply_packet = read_one_packet(istream, tunnel->recv_buffer, error);
    if (reply_packet == NULL) {
        snx_ssl_tunnel_free(tunnel);
        return NULL;
    }

    if (reply_packet->type != SNX_SLIM_CONTROL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "expected a control packet for the tunnel hello reply");
        snx_slim_packet_free(reply_packet);
        snx_ssl_tunnel_free(tunnel);
        return NULL;
    }

    reply_expr = snx_sexpr_parse(reply_packet->control_text, error);
    if (reply_expr == NULL) {
        snx_slim_packet_free(reply_packet);
        snx_ssl_tunnel_free(tunnel);
        return NULL;
    }

    if (g_strcmp0(snx_sexpr_object_name(reply_expr), "disconnect") == 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "gateway rejected the tunnel session: %s",
                   reply_packet->control_text);
        snx_sexpr_free(reply_expr);
        snx_slim_packet_free(reply_packet);
        snx_ssl_tunnel_free(tunnel);
        return NULL;
    }

    ok = snx_ssl_parse_hello_reply(reply_expr, out_reply, error);
    snx_sexpr_free(reply_expr);
    snx_slim_packet_free(reply_packet);

    if (!ok) {
        snx_ssl_tunnel_free(tunnel);
        return NULL;
    }

    /* The 15s timeout set above via g_socket_client_set_timeout() is baked
     * into this connection's GSocket at connect time and would otherwise
     * apply for the rest of the tunnel's life, including the downlink
     * thread's blocking read while waiting for the next packet. A gateway
     * that goes quiet for longer than 15s between packets/keepalives (a
     * normal idle period, not a failure) would then get its read killed by
     * a spurious timeout. Only the handshake above needs a bound; clear it
     * now so the ongoing read relies on the protocol-level keepalive-miss
     * detection (SNX_KEEPALIVE_MAX_MISSES in nm-snx-service.c) instead of a
     * fixed socket timeout. */
    g_socket_set_timeout(g_socket_connection_get_socket(tunnel->conn), 0);

    return tunnel;
}

void
snx_ssl_tunnel_free(SnxSslTunnel *tunnel)
{
    if (tunnel == NULL)
        return;

    g_clear_object(&tunnel->conn);
    g_clear_object(&tunnel->client);
    g_clear_pointer(&tunnel->recv_buffer, g_byte_array_unref);
    g_mutex_clear(&tunnel->write_lock);
    g_free(tunnel);
}

void
snx_ssl_tunnel_close(SnxSslTunnel *tunnel)
{
    /* shutdown() the raw socket fd directly, not just g_io_stream_close():
     * the downlink thread is typically blocked in a synchronous TLS read on
     * this same connection when this runs from the main thread, and GIO
     * does not guarantee g_io_stream_close() promptly unblocks a
     * concurrent synchronous read on the same stream from another thread.
     * A stuck read there means teardown_tunnel()'s g_thread_join() on that
     * thread never returns, which hangs Disconnect() itself -- and with it
     * this whole process, since main() is blocked inside the D-Bus method
     * call and never reaches g_main_loop_run() again to notice SIGTERM.
     * shutdown() is a POSIX-level operation on the fd: any blocking
     * read()/recv() using it is guaranteed to return immediately. */
    GSocket *sock = g_socket_connection_get_socket(tunnel->conn);

    if (sock != NULL)
        shutdown(g_socket_get_fd(sock), SHUT_RDWR);

    g_io_stream_close(G_IO_STREAM(tunnel->conn), NULL, NULL);
}

gboolean
snx_ssl_tunnel_send_data(SnxSslTunnel *tunnel, const guint8 *data, gsize len, GError **error)
{
    g_autoptr(GBytes) bytes = g_bytes_new(data, len);
    g_autoptr(SnxSlimPacket) packet = snx_slim_packet_new_data(bytes);
    gboolean ok;

    g_mutex_lock(&tunnel->write_lock);
    ok = write_packet(g_io_stream_get_output_stream(G_IO_STREAM(tunnel->conn)), packet, error);
    g_mutex_unlock(&tunnel->write_lock);

    return ok;
}

gboolean
snx_ssl_tunnel_send_keepalive(SnxSslTunnel *tunnel, GError **error)
{
    SnxWriter *root = snx_writer_new_object("keepalive");
    g_autofree char *text = NULL;
    g_autoptr(SnxSlimPacket) packet = NULL;
    gboolean ok;

    snx_writer_set_string(root, "id", "0");
    text = snx_writer_to_string(root);
    snx_writer_free(root);

    packet = snx_slim_packet_new_control(text);

    g_mutex_lock(&tunnel->write_lock);
    ok = write_packet(g_io_stream_get_output_stream(G_IO_STREAM(tunnel->conn)), packet, error);
    g_mutex_unlock(&tunnel->write_lock);

    return ok;
}

SnxSlimPacket *
snx_ssl_tunnel_receive(SnxSslTunnel *tunnel, GError **error)
{
    return read_one_packet(g_io_stream_get_input_stream(G_IO_STREAM(tunnel->conn)), tunnel->recv_buffer, error);
}
