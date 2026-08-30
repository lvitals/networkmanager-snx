/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-sexpr-writer.h"

typedef enum {
    SNX_WRITER_OBJECT,
    SNX_WRITER_VALUE,
} SnxWriterKind;

struct _SnxWriter {
    SnxWriterKind kind;

    /* SNX_WRITER_OBJECT */
    char *name;
    GPtrArray *keys;   /* char * */
    GPtrArray *values; /* SnxWriter * */

    /* SNX_WRITER_VALUE */
    char *value;
};

static SnxWriter *
writer_new_value(const char *value)
{
    SnxWriter *writer = g_new0(SnxWriter, 1);

    writer->kind = SNX_WRITER_VALUE;
    writer->value = g_strdup(value);
    return writer;
}

SnxWriter *
snx_writer_new_object(const char *name)
{
    SnxWriter *writer = g_new0(SnxWriter, 1);

    writer->kind = SNX_WRITER_OBJECT;
    writer->name = g_strdup(name);
    writer->keys = g_ptr_array_new_with_free_func(g_free);
    writer->values = g_ptr_array_new_with_free_func((GDestroyNotify) snx_writer_free);
    return writer;
}

void
snx_writer_free(SnxWriter *writer)
{
    if (writer == NULL)
        return;

    switch (writer->kind) {
    case SNX_WRITER_OBJECT:
        g_free(writer->name);
        g_ptr_array_unref(writer->keys);
        g_ptr_array_unref(writer->values);
        break;
    case SNX_WRITER_VALUE:
        g_free(writer->value);
        break;
    }

    g_free(writer);
}

static void
writer_add_field(SnxWriter *writer, const char *key, SnxWriter *value)
{
    g_return_if_fail(writer->kind == SNX_WRITER_OBJECT);

    g_ptr_array_add(writer->keys, g_strdup(key));
    g_ptr_array_add(writer->values, value);
}

void
snx_writer_set_string(SnxWriter *writer, const char *key, const char *value)
{
    if (value == NULL)
        return;

    writer_add_field(writer, key, writer_new_value(value));
}

void
snx_writer_set_uint(SnxWriter *writer, const char *key, guint value)
{
    g_autofree char *text = g_strdup_printf("%u", value);

    snx_writer_set_string(writer, key, text);
}

void
snx_writer_set_bool(SnxWriter *writer, const char *key, gboolean value)
{
    snx_writer_set_string(writer, key, value ? "true" : "false");
}

SnxWriter *
snx_writer_add_object(SnxWriter *writer, const char *key, const char *child_name)
{
    SnxWriter *child = snx_writer_new_object(child_name);

    writer_add_field(writer, key, child);
    return child;
}

static gboolean
value_needs_quoting(const char *value)
{
    for (const char *p = value; *p != '\0'; p++) {
        if (!g_ascii_isalnum(*p) && *p != '_')
            return TRUE;
    }
    return FALSE;
}

static void
append_indent(GString *out, guint level)
{
    for (guint i = 0; i < level; i++)
        g_string_append_c(out, '\t');
}

static void
serialize_node(GString *out, const SnxWriter *node, guint level)
{
    if (node->kind == SNX_WRITER_VALUE) {
        if (value_needs_quoting(node->value))
            g_string_append_printf(out, "(\"%s\")", node->value);
        else
            g_string_append_printf(out, "(%s)", node->value);
        return;
    }

    g_string_append_c(out, '(');
    if (node->name != NULL)
        g_string_append(out, node->name);

    for (guint i = 0; i < node->keys->len; i++) {
        g_string_append_c(out, '\n');
        append_indent(out, level + 1);
        g_string_append_c(out, ':');
        g_string_append(out, g_ptr_array_index(node->keys, i));
        g_string_append_c(out, ' ');
        serialize_node(out, g_ptr_array_index(node->values, i), level + 1);
    }

    g_string_append_c(out, ')');
}

char *
snx_writer_to_string(const SnxWriter *writer)
{
    GString *out = g_string_new(NULL);

    serialize_node(out, writer, 0);
    return g_string_free(out, FALSE);
}
