/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-slim.h"

#include "snx-errors.h"
#include "snx-sexpr.h"
#include "snx-ssl-tunnel-internal.h"

#include <glib.h>
#include <string.h>

/* Byte-level fixtures validated against real SLIM framing observed on the
 * wire against a production Check Point gateway. */

static void
test_parse_hello_reply_dns(void)
{
    const char *text =
        "(hello_reply\n"
        "    :version (1)\n"
        "    :protocol_version (1)\n"
        "    :OM (\n"
        "        :ipaddr (10.0.0.10)\n"
        "        :dns_servers (\n"
        "            : (10.0.0.1)\n"
        "            : (10.0.0.2)\n"
        "        )\n"
        "        :dns_suffix (\"domain1.com;domain2.com\")\n"
        "    )\n"
        "    :range (\n"
        "        : (\n"
        "            :from (10.0.0.0)\n"
        "            :to (10.255.255.255)\n"
        "        )\n"
        "    )\n"
        "    :timeouts (\n"
        "        :authentication (259193)\n"
        "        :keepalive (20)\n"
        "    )\n"
        "    :optional (\n"
        "        :subnet (255.255.255.0)\n"
        "    )\n"
        ")";
    g_autoptr(GError) error = NULL;
    SnxSexpr *expr = snx_sexpr_parse(text, &error);
    SnxSslHelloReply reply = {0};

    g_assert_no_error(error);
    g_assert_nonnull(expr);
    g_assert_true(snx_ssl_parse_hello_reply(expr, &reply, &error));
    g_assert_no_error(error);

    g_assert_cmpstr(reply.assigned_ip, ==, "10.0.0.10");
    g_assert_cmpstr(reply.subnet_mask, ==, "255.255.255.0");
    g_assert_cmpuint(reply.keepalive_seconds, ==, 20);
    g_assert_cmpuint(reply.dns_servers->len, ==, 2);
    g_assert_cmpstr(g_ptr_array_index(reply.dns_servers, 0), ==, "10.0.0.1");
    g_assert_cmpstr(g_ptr_array_index(reply.dns_servers, 1), ==, "10.0.0.2");
    g_assert_cmpuint(reply.search_domains->len, ==, 2);
    g_assert_cmpstr(g_ptr_array_index(reply.search_domains, 0), ==, "domain1.com");
    g_assert_cmpstr(g_ptr_array_index(reply.search_domains, 1), ==, "domain2.com");
    g_assert_cmpuint(reply.ranges->len, ==, 1);

    snx_ssl_hello_reply_clear(&reply);
    snx_sexpr_free(expr);
}

static void
test_encode_data_packet(void)
{
    g_autoptr(GBytes) data = g_bytes_new_static((const guint8[]) {1, 2, 3, 4, 5}, 5);
    g_autoptr(SnxSlimPacket) packet = snx_slim_packet_new_data(data);
    g_autoptr(GBytes) encoded = snx_slim_encode(packet);
    static const guint8 expected[] = {0, 0, 0, 5, 0, 0, 0, 2, 1, 2, 3, 4, 5};
    gsize len;
    const guint8 *bytes = g_bytes_get_data(encoded, &len);

    g_assert_cmpuint(len, ==, sizeof(expected));
    g_assert_cmpint(memcmp(bytes, expected, len), ==, 0);
}

static void
test_encode_control_packet_is_nul_terminated(void)
{
    const char *text = "(keepalive :id (0))";
    g_autoptr(SnxSlimPacket) packet = snx_slim_packet_new_control(text);
    g_autoptr(GBytes) encoded = snx_slim_encode(packet);
    gsize len;
    const guint8 *bytes = g_bytes_get_data(encoded, &len);
    guint32 payload_len =
        ((guint32) bytes[0] << 24) | ((guint32) bytes[1] << 16) | ((guint32) bytes[2] << 8) | bytes[3];
    guint32 type = ((guint32) bytes[4] << 24) | ((guint32) bytes[5] << 16) | ((guint32) bytes[6] << 8) | bytes[7];

    g_assert_cmpuint(payload_len, ==, strlen(text) + 1);
    g_assert_cmpuint(type, ==, 1); /* PKT_CONTROL */
    g_assert_cmpuint(len, ==, 8 + payload_len);
    g_assert_cmpint(memcmp(bytes + 8, text, strlen(text)), ==, 0);
    g_assert_cmpuint(bytes[len - 1], ==, 0);
}

static void
test_decode_data_roundtrip(void)
{
    guint8 raw[] = {9, 8, 7, 6};
    g_autoptr(GBytes) data = g_bytes_new_static(raw, sizeof(raw));
    g_autoptr(SnxSlimPacket) packet = snx_slim_packet_new_data(data);
    g_autoptr(GBytes) encoded = snx_slim_encode(packet);
    gsize len;
    const guint8 *bytes = g_bytes_get_data(encoded, &len);
    g_autoptr(GError) error = NULL;
    gsize consumed = 0;
    SnxSlimPacket *decoded = snx_slim_decode(bytes, len, &consumed, &error);
    gsize decoded_len;
    const guint8 *decoded_bytes;

    g_assert_no_error(error);
    g_assert_nonnull(decoded);
    g_assert_cmpuint(consumed, ==, len);
    g_assert_cmpint(decoded->type, ==, SNX_SLIM_DATA);

    decoded_bytes = g_bytes_get_data(decoded->data, &decoded_len);
    g_assert_cmpuint(decoded_len, ==, sizeof(raw));
    g_assert_cmpint(memcmp(decoded_bytes, raw, sizeof(raw)), ==, 0);

    snx_slim_packet_free(decoded);
}

static void
test_decode_control_roundtrip_ignores_trailing_nul(void)
{
    const char *text = "(keepalive :id (0))";
    g_autoptr(SnxSlimPacket) packet = snx_slim_packet_new_control(text);
    g_autoptr(GBytes) encoded = snx_slim_encode(packet);
    gsize len;
    const guint8 *bytes = g_bytes_get_data(encoded, &len);
    g_autoptr(GError) error = NULL;
    gsize consumed = 0;
    SnxSlimPacket *decoded = snx_slim_decode(bytes, len, &consumed, &error);

    g_assert_no_error(error);
    g_assert_nonnull(decoded);
    g_assert_cmpuint(consumed, ==, len);
    g_assert_cmpint(decoded->type, ==, SNX_SLIM_CONTROL);
    g_assert_cmpstr(decoded->control_text, ==, text);

    snx_slim_packet_free(decoded);
}

static void
test_decode_returns_none_on_partial_input(void)
{
    static const guint8 too_short[] = {0, 0, 0};
    static const guint8 incomplete_payload[] = {0, 0, 0, 4, 0, 0, 0, 2, 1, 2, 3};
    g_autoptr(GError) error = NULL;
    gsize consumed = 999;
    SnxSlimPacket *decoded;

    decoded = snx_slim_decode(too_short, sizeof(too_short), &consumed, &error);
    g_assert_null(decoded);
    g_assert_no_error(error);
    g_assert_cmpuint(consumed, ==, 0);

    consumed = 999;
    decoded = snx_slim_decode(incomplete_payload, sizeof(incomplete_payload), &consumed, &error);
    g_assert_null(decoded);
    g_assert_no_error(error);
    g_assert_cmpuint(consumed, ==, 0);
}

static void
test_decode_leaves_trailing_bytes_of_next_packet(void)
{
    static const guint8 buf[] = {0, 0, 0, 1, 0, 0, 0, 2, 0xaa, 0, 0, 0, 1};
    g_autoptr(GError) error = NULL;
    gsize consumed = 0;
    SnxSlimPacket *decoded = snx_slim_decode(buf, sizeof(buf), &consumed, &error);
    gsize decoded_len;
    const guint8 *decoded_bytes;

    g_assert_no_error(error);
    g_assert_nonnull(decoded);
    g_assert_cmpuint(consumed, ==, 9); /* header (8) + 1-byte payload */

    decoded_bytes = g_bytes_get_data(decoded->data, &decoded_len);
    g_assert_cmpuint(decoded_len, ==, 1);
    g_assert_cmpuint(decoded_bytes[0], ==, 0xaa);

    snx_slim_packet_free(decoded);

    /* Remaining 4 bytes are the start of a second header with no payload yet. */
    g_assert_cmpuint(sizeof(buf) - consumed, ==, 4);
}

static void
test_decode_rejects_unknown_packet_type(void)
{
    static const guint8 buf[] = {0, 0, 0, 1, 0, 0, 0, 7, 0xaa};
    g_autoptr(GError) error = NULL;
    gsize consumed = 0;
    SnxSlimPacket *decoded = snx_slim_decode(buf, sizeof(buf), &consumed, &error);

    g_assert_null(decoded);
    g_assert_error(error, SNX_ERROR, SNX_ERROR_PARSE);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/slim/parse-hello-reply-dns", test_parse_hello_reply_dns);
    g_test_add_func("/slim/encode-data-packet", test_encode_data_packet);
    g_test_add_func("/slim/encode-control-packet-is-nul-terminated", test_encode_control_packet_is_nul_terminated);
    g_test_add_func("/slim/decode-data-roundtrip", test_decode_data_roundtrip);
    g_test_add_func("/slim/decode-control-roundtrip-ignores-trailing-nul",
                    test_decode_control_roundtrip_ignores_trailing_nul);
    g_test_add_func("/slim/decode-returns-none-on-partial-input", test_decode_returns_none_on_partial_input);
    g_test_add_func("/slim/decode-leaves-trailing-bytes-of-next-packet",
                    test_decode_leaves_trailing_bytes_of_next_packet);
    g_test_add_func("/slim/decode-rejects-unknown-packet-type", test_decode_rejects_unknown_packet_type);
    return g_test_run();
}
