/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_SEXPR_WRITER_H
#define SNX_SEXPR_WRITER_H

#include <glib.h>

/* Builds and serializes the Check Point CCC S-expression wire format:
 * (Name
 *      :key1 (value1)
 *      :key2 (
 *          :nested (value)))
 *
 * This is the request-building counterpart to the read-only parser in
 * snx-sexpr.h. Fields set to a NULL string are omitted entirely, matching
 * how the reference client omits absent (Option::None) fields rather than
 * emitting an empty value. */

typedef struct _SnxWriter SnxWriter;

SnxWriter *snx_writer_new_object(const char *name);
void snx_writer_free(SnxWriter *writer);

/* value == NULL omits the field. */
void snx_writer_set_string(SnxWriter *writer, const char *key, const char *value);
void snx_writer_set_uint(SnxWriter *writer, const char *key, guint value);
void snx_writer_set_bool(SnxWriter *writer, const char *key, gboolean value);

/* Creates a nested object, attaches it under key, and returns it (still
 * owned by the parent) so the caller can keep filling it in. */
SnxWriter *snx_writer_add_object(SnxWriter *writer, const char *key, const char *child_name);

char *snx_writer_to_string(const SnxWriter *writer);

#endif
