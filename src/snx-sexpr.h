/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_SEXPR_H
#define SNX_SEXPR_H

#include <glib.h>

typedef enum {
    SNX_SEXPR_ATOM,
    SNX_SEXPR_LIST,
} SnxSexprType;

typedef struct _SnxSexpr SnxSexpr;

struct _SnxSexpr {
    SnxSexprType type;
    char *atom;
    GPtrArray *children;
};

SnxSexpr *snx_sexpr_parse(const char *input, GError **error);
void snx_sexpr_free(SnxSexpr *expr);
guint snx_sexpr_child_count(const SnxSexpr *expr);
const SnxSexpr *snx_sexpr_child(const SnxSexpr *expr, guint index);
const char *snx_sexpr_atom(const SnxSexpr *expr);

/*
 * Helpers for reading the labelled-field objects used by the CCC protocol:
 * (Name :key1 (value1) :key2 (nested :inner (value2)))
 *
 * A "field value" as returned by these functions is still the parenthesised
 * list wrapping the actual content (e.g. the list for ":id (1)" is the
 * single-atom list "(1)"); use snx_sexpr_value_string() to unwrap a leaf.
 */

/* Navigates a colon-separated path of field names, e.g. "ResponseData:session_id". */
const SnxSexpr *snx_sexpr_get(const SnxSexpr *expr, const char *path);

/* Unwraps a single-atom value list (e.g. "(1)" or ("text")) to its string. */
const char *snx_sexpr_value_string(const SnxSexpr *expr);

/* Combines snx_sexpr_get() and snx_sexpr_value_string(). */
const char *snx_sexpr_get_string(const SnxSexpr *expr, const char *path);

/* The leading unlabelled atom of a labelled object, e.g. "hello_reply" for
 * "(hello_reply :key (value))"; NULL for an unnamed object. */
const char *snx_sexpr_object_name(const SnxSexpr *expr);

/* Generic (key, value) field iteration over a labelled object, for objects
 * whose field names are data (e.g. login options keyed by their id) rather
 * than known ahead of time. */
guint snx_sexpr_field_count(const SnxSexpr *object);
const char *snx_sexpr_field_key(const SnxSexpr *object, guint index);
const SnxSexpr *snx_sexpr_field_value(const SnxSexpr *object, guint index);

#endif
