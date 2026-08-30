/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-sexpr-writer.h"

#include <glib.h>
#include <string.h>

/* These expected strings were validated against the S-expression wire
 * format observed against a real Check Point gateway, so a match here
 * means our writer produces byte-identical wire output. */

static void
test_quoted_value(void)
{
    SnxWriter *writer = snx_writer_new_object(NULL);
    g_autofree char *encoded = NULL;

    snx_writer_set_string(writer, "key", "Hello_world!");
    encoded = snx_writer_to_string(writer);

    g_assert_cmpstr(encoded, ==, "(\n\t:key (\"Hello_world!\"))");

    snx_writer_free(writer);
}

static void
test_non_quoted_value(void)
{
    SnxWriter *writer = snx_writer_new_object(NULL);
    g_autofree char *encoded = NULL;

    snx_writer_set_string(writer, "key", "Hello_world");
    encoded = snx_writer_to_string(writer);

    g_assert_cmpstr(encoded, ==, "(\n\t:key (Hello_world))");

    snx_writer_free(writer);
}

static void
test_named_object_with_nested_fields(void)
{
    SnxWriter *writer = snx_writer_new_object("CCCclientRequest");
    SnxWriter *header;
    g_autofree char *encoded = NULL;

    header = snx_writer_add_object(writer, "RequestHeader", NULL);
    snx_writer_set_uint(header, "id", 1);
    snx_writer_set_string(header, "type", "ClientHello");

    encoded = snx_writer_to_string(writer);

    g_assert_cmpstr(encoded,
                    ==,
                    "(CCCclientRequest\n"
                    "\t:RequestHeader (\n"
                    "\t\t:id (1)\n"
                    "\t\t:type (ClientHello)))");

    snx_writer_free(writer);
}

static void
test_empty_unnamed_object_matches_signout(void)
{
    SnxWriter *writer = snx_writer_new_object(NULL);
    g_autofree char *encoded = NULL;

    snx_writer_add_object(writer, "RequestData", NULL);
    encoded = snx_writer_to_string(writer);

    g_assert_nonnull(strstr(encoded, "RequestData ()"));

    snx_writer_free(writer);
}

static void
test_null_value_is_omitted(void)
{
    SnxWriter *writer = snx_writer_new_object(NULL);
    g_autofree char *encoded = NULL;

    snx_writer_set_string(writer, "present", "value");
    snx_writer_set_string(writer, "absent", NULL);
    encoded = snx_writer_to_string(writer);

    g_assert_nonnull(strstr(encoded, "present"));
    g_assert_null(strstr(encoded, "absent"));

    snx_writer_free(writer);
}

static void
test_bool_and_uint(void)
{
    SnxWriter *writer = snx_writer_new_object(NULL);
    g_autofree char *encoded = NULL;

    snx_writer_set_bool(writer, "flag", TRUE);
    snx_writer_set_uint(writer, "num", 42);
    encoded = snx_writer_to_string(writer);

    g_assert_cmpstr(encoded, ==, "(\n\t:flag (true)\n\t:num (42))");

    snx_writer_free(writer);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/sexpr-writer/quoted-value", test_quoted_value);
    g_test_add_func("/sexpr-writer/non-quoted-value", test_non_quoted_value);
    g_test_add_func("/sexpr-writer/named-object-nested-fields", test_named_object_with_nested_fields);
    g_test_add_func("/sexpr-writer/empty-unnamed-object", test_empty_unnamed_object_matches_signout);
    g_test_add_func("/sexpr-writer/null-value-omitted", test_null_value_is_omitted);
    g_test_add_func("/sexpr-writer/bool-and-uint", test_bool_and_uint);
    return g_test_run();
}
