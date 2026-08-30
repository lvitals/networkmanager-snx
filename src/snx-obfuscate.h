/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_OBFUSCATE_H
#define SNX_OBFUSCATE_H

#include <glib.h>

char *snx_obfuscate(const guint8 *data, gsize len);
gboolean snx_deobfuscate(const char *hex, guint8 **out_data, gsize *out_len, GError **error);

#endif
