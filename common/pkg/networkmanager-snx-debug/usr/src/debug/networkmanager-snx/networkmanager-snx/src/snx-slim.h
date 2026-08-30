/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_SLIM_H
#define SNX_SLIM_H

#include <glib.h>

/*
 * "SLIM" is Check Point's framing protocol for the SSL VPN tunnel data
 * connection: once authenticated, a persistent TLS connection carries a
 * stream of these length-prefixed packets (control S-expressions such as
 * the tunnel client_hello/hello_reply/keepalive, or raw tunneled IP data):
 *
 *   [4 bytes: payload length, big-endian]
 *   [4 bytes: packet type, big-endian: 1 = control, 2 = data]
 *   [payload]
 *
 * A control payload is the S-expression text plus one trailing NUL byte
 * (included in the length); a data payload is the raw tunneled packet.
 */

typedef enum {
    SNX_SLIM_CONTROL,
    SNX_SLIM_DATA,
} SnxSlimPacketType;

typedef struct {
    SnxSlimPacketType type;
    char *control_text;  /* SNX_SLIM_CONTROL only */
    GBytes *data;         /* SNX_SLIM_DATA only */
} SnxSlimPacket;

SnxSlimPacket *snx_slim_packet_new_control(const char *text);
SnxSlimPacket *snx_slim_packet_new_data(GBytes *data);
void snx_slim_packet_free(SnxSlimPacket *packet);

/* Serializes one packet into the wire format. */
GBytes *snx_slim_encode(const SnxSlimPacket *packet);

/*
 * Attempts to decode one packet from the front of buffer[0..len). On a
 * complete packet, returns it and sets *consumed to the number of bytes
 * used. If there isn't a full packet yet, returns NULL with *consumed set
 * to 0 and *error left unset. On a malformed/unknown packet, returns NULL
 * and sets *error.
 */
SnxSlimPacket *snx_slim_decode(const guint8 *buffer, gsize len, gsize *consumed, GError **error);

G_DEFINE_AUTOPTR_CLEANUP_FUNC(SnxSlimPacket, snx_slim_packet_free)

#endif
