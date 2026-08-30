/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-slim.h"

#include "snx-errors.h"

#define SNX_SLIM_HEADER_LEN 8
#define SNX_SLIM_PKT_CONTROL 1
#define SNX_SLIM_PKT_DATA 2

SnxSlimPacket *
snx_slim_packet_new_control(const char *text)
{
    SnxSlimPacket *packet = g_new0(SnxSlimPacket, 1);

    packet->type = SNX_SLIM_CONTROL;
    packet->control_text = g_strdup(text);
    return packet;
}

SnxSlimPacket *
snx_slim_packet_new_data(GBytes *data)
{
    SnxSlimPacket *packet = g_new0(SnxSlimPacket, 1);

    packet->type = SNX_SLIM_DATA;
    packet->data = g_bytes_ref(data);
    return packet;
}

void
snx_slim_packet_free(SnxSlimPacket *packet)
{
    if (packet == NULL)
        return;

    g_free(packet->control_text);
    g_clear_pointer(&packet->data, g_bytes_unref);
    g_free(packet);
}

static void
put_be32(guint8 *out, guint32 value)
{
    out[0] = (guint8) (value >> 24);
    out[1] = (guint8) (value >> 16);
    out[2] = (guint8) (value >> 8);
    out[3] = (guint8) value;
}

static guint32
get_be32(const guint8 *in)
{
    return ((guint32) in[0] << 24) | ((guint32) in[1] << 16) | ((guint32) in[2] << 8) | (guint32) in[3];
}

GBytes *
snx_slim_encode(const SnxSlimPacket *packet)
{
    gsize payload_len;
    const guint8 *payload_data = NULL;
    g_autofree guint8 *control_payload = NULL;
    guint8 header[SNX_SLIM_HEADER_LEN];
    guint8 *out;
    guint32 type;

    if (packet->type == SNX_SLIM_CONTROL) {
        gsize text_len = strlen(packet->control_text);

        payload_len = text_len + 1;
        control_payload = g_malloc(payload_len);
        memcpy(control_payload, packet->control_text, text_len);
        control_payload[text_len] = '\0';
        payload_data = control_payload;
        type = SNX_SLIM_PKT_CONTROL;
    } else {
        payload_data = g_bytes_get_data(packet->data, &payload_len);
        type = SNX_SLIM_PKT_DATA;
    }

    put_be32(header, (guint32) payload_len);
    put_be32(header + 4, type);

    out = g_malloc(SNX_SLIM_HEADER_LEN + payload_len);
    memcpy(out, header, SNX_SLIM_HEADER_LEN);
    memcpy(out + SNX_SLIM_HEADER_LEN, payload_data, payload_len);

    return g_bytes_new_take(out, SNX_SLIM_HEADER_LEN + payload_len);
}

SnxSlimPacket *
snx_slim_decode(const guint8 *buffer, gsize len, gsize *consumed, GError **error)
{
    guint32 payload_len;
    guint32 type;
    const guint8 *payload;
    SnxSlimPacket *packet;

    *consumed = 0;

    if (len < SNX_SLIM_HEADER_LEN)
        return NULL;

    payload_len = get_be32(buffer);
    if (len < (gsize) SNX_SLIM_HEADER_LEN + payload_len)
        return NULL;

    type = get_be32(buffer + 4);
    payload = buffer + SNX_SLIM_HEADER_LEN;

    switch (type) {
    case SNX_SLIM_PKT_CONTROL: {
        /* The encoder always appends one trailing NUL to the S-expression
         * text, counted in payload_len; drop it so control_text is a plain
         * C string with no embedded terminator. */
        gsize text_len = payload_len > 0 && payload[payload_len - 1] == '\0' ? payload_len - 1 : payload_len;

        packet = g_new0(SnxSlimPacket, 1);
        packet->type = SNX_SLIM_CONTROL;
        packet->control_text = g_strndup((const char *) payload, text_len);
        break;
    }
    case SNX_SLIM_PKT_DATA:
        packet = g_new0(SnxSlimPacket, 1);
        packet->type = SNX_SLIM_DATA;
        packet->data = g_bytes_new(payload, payload_len);
        break;
    default:
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "unknown SLIM packet type %u", type);
        return NULL;
    }

    *consumed = SNX_SLIM_HEADER_LEN + payload_len;
    return packet;
}
