/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-obfuscate.h"

#include "snx-errors.h"

#include <string.h>

/*
 * Check Point's CCC protocol never sends credentials in the clear, even
 * though the whole request already goes over TLS: values are additionally
 * run through this reversible byte-scrambling scheme before being placed in
 * the S-expression body. This is not encryption and provides no additional
 * confidentiality; it exists purely so the wire format matches what real
 * gateways expect. The table and transform below are the publicly known
 * Check Point SNX obfuscation scheme (also reimplemented by other
 * independent open-source SNX clients).
 */
static const guint8 xor_table[] = {
    45, 79, 68, 73, 70, 73, 69, 68, 38, 87, 48, 82, 79, 80, 69, 82, 84, 89, 51, 72, 69, 69, 84,
    55, 73, 84, 72, 47, 43, 52, 72, 69, 51, 72, 69, 69, 84, 41, 36, 51, 63, 44, 36, 33, 48, 63,
    33, 53, 63, 48, 50, 47, 48, 37, 50, 52, 41, 37, 51, 46, 53, 44, 44, 16, 38, 55, 63, 55, 48,
    63, 47, 34, 42, 37, 35, 52, 51,
};

static guint8
translate_byte(gsize index, guint8 c)
{
    guint8 v = (guint8) ((c % 255) ^ xor_table[index % G_N_ELEMENTS(xor_table)]);

    return v == 0 ? 255 : v;
}

static guint8 *
translate(const guint8 *data, gsize len)
{
    guint8 *tmp = g_malloc(len > 0 ? len : 1);
    guint8 *out = g_malloc(len > 0 ? len : 1);
    gsize i;

    for (i = 0; i < len; i++)
        tmp[i] = translate_byte(i, data[i]);
    for (i = 0; i < len; i++)
        out[i] = tmp[len - 1 - i];

    g_free(tmp);
    return out;
}

char *
snx_obfuscate(const guint8 *data, gsize len)
{
    g_autofree guint8 *translated = translate(data, len);
    GString *hex = g_string_sized_new(len * 2);
    gsize i;

    for (i = 0; i < len; i++)
        g_string_append_printf(hex, "%02x", translated[i]);

    return g_string_free(hex, FALSE);
}

gboolean
snx_deobfuscate(const char *hex, guint8 **out_data, gsize *out_len, GError **error)
{
    gsize hex_len = strlen(hex);
    gsize len;
    guint8 *unhexed;
    guint8 *reversed;
    guint8 *decoded;
    gsize i;

    if (hex_len % 2 != 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "obfuscated value has odd length");
        return FALSE;
    }

    len = hex_len / 2;
    unhexed = g_malloc(len > 0 ? len : 1);
    for (i = 0; i < len; i++) {
        gint hi = g_ascii_xdigit_value(hex[2 * i]);
        gint lo = g_ascii_xdigit_value(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            g_free(unhexed);
            g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "obfuscated value is not valid hex");
            return FALSE;
        }
        unhexed[i] = (guint8) ((hi << 4) | lo);
    }

    reversed = g_malloc(len > 0 ? len : 1);
    for (i = 0; i < len; i++)
        reversed[i] = unhexed[len - 1 - i];
    g_free(unhexed);

    decoded = translate(reversed, len);
    g_free(reversed);

    *out_data = g_malloc(len > 0 ? len : 1);
    for (i = 0; i < len; i++)
        (*out_data)[i] = decoded[len - 1 - i];
    g_free(decoded);

    *out_len = len;
    return TRUE;
}
