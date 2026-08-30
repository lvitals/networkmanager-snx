/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-sexpr.h"

#include "snx-errors.h"

#include <ctype.h>
#include <string.h>

typedef struct {
    const char *input;
    gsize pos;
} Parser;

static void
skip_ws(Parser *parser)
{
    while (g_ascii_isspace(parser->input[parser->pos]))
        parser->pos++;
}

static SnxSexpr *
sexpr_new(SnxSexprType type)
{
    SnxSexpr *expr = g_new0(SnxSexpr, 1);
    expr->type = type;
    if (type == SNX_SEXPR_LIST)
        expr->children = g_ptr_array_new_with_free_func((GDestroyNotify) snx_sexpr_free);
    return expr;
}

static SnxSexpr *parse_expr(Parser *parser, GError **error);

static SnxSexpr *
parse_quoted_atom(Parser *parser, GError **error)
{
    GString *value = g_string_new(NULL);
    SnxSexpr *expr;

    parser->pos++;
    while (parser->input[parser->pos] != '\0') {
        char ch = parser->input[parser->pos++];
        if (ch == '"') {
            expr = sexpr_new(SNX_SEXPR_ATOM);
            expr->atom = g_string_free(value, FALSE);
            return expr;
        }
        if (ch == '\\' && parser->input[parser->pos] != '\0') {
            char escaped = parser->input[parser->pos++];
            switch (escaped) {
            case 'n':
                g_string_append_c(value, '\n');
                break;
            case 'r':
                g_string_append_c(value, '\r');
                break;
            case 't':
                g_string_append_c(value, '\t');
                break;
            default:
                g_string_append_c(value, escaped);
                break;
            }
        } else {
            g_string_append_c(value, ch);
        }
    }

    g_string_free(value, TRUE);
    g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "unterminated quoted atom");
    return NULL;
}

static SnxSexpr *
parse_atom(Parser *parser, GError **error)
{
    gsize start = parser->pos;
    SnxSexpr *expr;

    while (parser->input[parser->pos] != '\0' &&
           !g_ascii_isspace(parser->input[parser->pos]) &&
           parser->input[parser->pos] != '(' &&
           parser->input[parser->pos] != ')') {
        parser->pos++;
    }

    if (parser->pos == start) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "expected atom at byte %" G_GSIZE_FORMAT, parser->pos);
        return NULL;
    }

    expr = sexpr_new(SNX_SEXPR_ATOM);
    expr->atom = g_strndup(parser->input + start, parser->pos - start);
    return expr;
}

static SnxSexpr *
parse_list(Parser *parser, GError **error)
{
    SnxSexpr *list = sexpr_new(SNX_SEXPR_LIST);

    parser->pos++;
    for (;;) {
        skip_ws(parser);

        if (parser->input[parser->pos] == '\0') {
            snx_sexpr_free(list);
            g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "unterminated list");
            return NULL;
        }

        if (parser->input[parser->pos] == ')') {
            parser->pos++;
            return list;
        }

        SnxSexpr *child = parse_expr(parser, error);
        if (child == NULL) {
            snx_sexpr_free(list);
            return NULL;
        }
        g_ptr_array_add(list->children, child);
    }
}

static SnxSexpr *
parse_expr(Parser *parser, GError **error)
{
    skip_ws(parser);

    if (parser->input[parser->pos] == '(')
        return parse_list(parser, error);
    if (parser->input[parser->pos] == '"')
        return parse_quoted_atom(parser, error);
    return parse_atom(parser, error);
}

SnxSexpr *
snx_sexpr_parse(const char *input, GError **error)
{
    Parser parser = {
        .input = input,
        .pos = 0,
    };
    SnxSexpr *expr;

    if (input == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "input is null");
        return NULL;
    }

    expr = parse_expr(&parser, error);
    if (expr == NULL)
        return NULL;

    skip_ws(&parser);
    if (parser.input[parser.pos] != '\0') {
        snx_sexpr_free(expr);
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "trailing input at byte %" G_GSIZE_FORMAT, parser.pos);
        return NULL;
    }

    return expr;
}

void
snx_sexpr_free(SnxSexpr *expr)
{
    if (expr == NULL)
        return;

    g_free(expr->atom);
    if (expr->children != NULL)
        g_ptr_array_unref(expr->children);
    g_free(expr);
}

guint
snx_sexpr_child_count(const SnxSexpr *expr)
{
    if (expr == NULL || expr->type != SNX_SEXPR_LIST)
        return 0;
    return expr->children->len;
}

const SnxSexpr *
snx_sexpr_child(const SnxSexpr *expr, guint index)
{
    if (expr == NULL || expr->type != SNX_SEXPR_LIST || index >= expr->children->len)
        return NULL;
    return g_ptr_array_index(expr->children, index);
}

const char *
snx_sexpr_atom(const SnxSexpr *expr)
{
    if (expr == NULL || expr->type != SNX_SEXPR_ATOM)
        return NULL;
    return expr->atom;
}

/* A labelled object's first child is a bare name atom (no leading ':') when
 * the object is named; unnamed objects start directly with a ":key" atom. */
static guint
field_start_index(const SnxSexpr *object)
{
    const SnxSexpr *first;
    const char *first_atom;

    if (snx_sexpr_child_count(object) == 0)
        return 0;

    first = snx_sexpr_child(object, 0);
    first_atom = snx_sexpr_atom(first);
    return (first_atom != NULL && first_atom[0] != ':') ? 1 : 0;
}

guint
snx_sexpr_field_count(const SnxSexpr *object)
{
    guint n = snx_sexpr_child_count(object);
    guint start = field_start_index(object);

    return n > start ? (n - start) / 2 : 0;
}

const char *
snx_sexpr_field_key(const SnxSexpr *object, guint index)
{
    guint start = field_start_index(object);
    const SnxSexpr *key_node = snx_sexpr_child(object, start + index * 2);
    const char *key_atom = snx_sexpr_atom(key_node);

    if (key_atom == NULL || key_atom[0] != ':')
        return NULL;
    return key_atom + 1;
}

const SnxSexpr *
snx_sexpr_field_value(const SnxSexpr *object, guint index)
{
    guint start = field_start_index(object);

    return snx_sexpr_child(object, start + index * 2 + 1);
}

static const SnxSexpr *
find_field(const SnxSexpr *object, const char *key)
{
    guint count = snx_sexpr_field_count(object);

    for (guint i = 0; i < count; i++) {
        const char *field_key = snx_sexpr_field_key(object, i);

        if (field_key != NULL && g_strcmp0(field_key, key) == 0)
            return snx_sexpr_field_value(object, i);
    }
    return NULL;
}

const SnxSexpr *
snx_sexpr_get(const SnxSexpr *expr, const char *path)
{
    g_auto(GStrv) parts = g_strsplit(path, ":", -1);
    const SnxSexpr *current = expr;

    for (guint i = 0; parts[i] != NULL && current != NULL; i++) {
        if (*parts[i] == '\0')
            continue;
        current = find_field(current, parts[i]);
    }

    return current;
}

const char *
snx_sexpr_value_string(const SnxSexpr *expr)
{
    if (expr == NULL || snx_sexpr_child_count(expr) != 1)
        return NULL;
    return snx_sexpr_atom(snx_sexpr_child(expr, 0));
}

const char *
snx_sexpr_get_string(const SnxSexpr *expr, const char *path)
{
    return snx_sexpr_value_string(snx_sexpr_get(expr, path));
}

const char *
snx_sexpr_object_name(const SnxSexpr *expr)
{
    const SnxSexpr *first;
    const char *first_atom;

    if (snx_sexpr_child_count(expr) == 0)
        return NULL;

    first = snx_sexpr_child(expr, 0);
    first_atom = snx_sexpr_atom(first);
    return (first_atom != NULL && first_atom[0] != ':') ? first_atom : NULL;
}
