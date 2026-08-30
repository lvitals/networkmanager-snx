/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-sexpr.h"
#include "snx-errors.h"

#include <glib.h>

static void
test_parse_simple_list(void)
{
    g_autoptr(GError) error = NULL;
    SnxSexpr *expr = snx_sexpr_parse("(client_hello (protocol ipsec) (server \"vpn.example.com\"))", &error);
    const SnxSexpr *child;

    g_assert_no_error(error);
    g_assert_nonnull(expr);
    g_assert_cmpuint(snx_sexpr_child_count(expr), ==, 3);
    child = snx_sexpr_child(expr, 0);
    g_assert_cmpstr(snx_sexpr_atom(child), ==, "client_hello");

    snx_sexpr_free(expr);
}

static void
test_parse_escaped_string(void)
{
    g_autoptr(GError) error = NULL;
    SnxSexpr *expr = snx_sexpr_parse("\"line\\nvalue\"", &error);

    g_assert_no_error(error);
    g_assert_nonnull(expr);
    g_assert_cmpstr(snx_sexpr_atom(expr), ==, "line\nvalue");

    snx_sexpr_free(expr);
}

static void
test_get_navigates_named_and_unnamed_objects(void)
{
    g_autoptr(GError) error = NULL;
    SnxSexpr *expr = snx_sexpr_parse("(CCCserverResponse\n"
                                     "\t:ResponseHeader (\n"
                                     "\t\t:id (1)\n"
                                     "\t\t:type (ClientHello))\n"
                                     "\t:ResponseData (\n"
                                     "\t\t:session_id (\"abc123\")\n"
                                     "\t\t:authn_status (done)))",
                                     &error);

    g_assert_no_error(error);
    g_assert_nonnull(expr);

    g_assert_cmpstr(snx_sexpr_get_string(expr, "ResponseHeader:id"), ==, "1");
    g_assert_cmpstr(snx_sexpr_get_string(expr, "ResponseHeader:type"), ==, "ClientHello");
    g_assert_cmpstr(snx_sexpr_get_string(expr, "ResponseData:session_id"), ==, "abc123");
    g_assert_cmpstr(snx_sexpr_get_string(expr, "ResponseData:authn_status"), ==, "done");
    g_assert_null(snx_sexpr_get_string(expr, "ResponseData:missing"));
    g_assert_null(snx_sexpr_get_string(expr, "does_not:exist"));

    snx_sexpr_free(expr);
}

static void
test_field_iteration_over_keyed_map(void)
{
    g_autoptr(GError) error = NULL;
    SnxSexpr *expr = snx_sexpr_parse("(\n"
                                     "\t:login_options_list (\n"
                                     "\t\t:vpn_Username_Password (\n"
                                     "\t\t\t:id (vpn_Username_Password)\n"
                                     "\t\t\t:display_name (\"Username and password\"))\n"
                                     "\t\t:PMC (\n"
                                     "\t\t\t:id (PMC)\n"
                                     "\t\t\t:display_name (\"PMC\"))))",
                                     &error);
    const SnxSexpr *list;

    g_assert_no_error(error);
    g_assert_nonnull(expr);

    list = snx_sexpr_get(expr, "login_options_list");
    g_assert_nonnull(list);
    g_assert_cmpuint(snx_sexpr_field_count(list), ==, 2);
    g_assert_cmpstr(snx_sexpr_field_key(list, 0), ==, "vpn_Username_Password");
    g_assert_cmpstr(snx_sexpr_get_string(snx_sexpr_field_value(list, 0), "display_name"),
                    ==,
                    "Username and password");
    g_assert_cmpstr(snx_sexpr_field_key(list, 1), ==, "PMC");
    g_assert_cmpstr(snx_sexpr_get_string(snx_sexpr_field_value(list, 1), "id"), ==, "PMC");

    snx_sexpr_free(expr);
}

static void
test_parse_error(void)
{
    g_autoptr(GError) error = NULL;
    SnxSexpr *expr = snx_sexpr_parse("(unterminated", &error);

    g_assert_null(expr);
    g_assert_error(error, SNX_ERROR, SNX_ERROR_PARSE);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/sexpr/simple-list", test_parse_simple_list);
    g_test_add_func("/sexpr/escaped-string", test_parse_escaped_string);
    g_test_add_func("/sexpr/get-navigates-named-and-unnamed-objects", test_get_navigates_named_and_unnamed_objects);
    g_test_add_func("/sexpr/field-iteration-over-keyed-map", test_field_iteration_over_keyed_map);
    g_test_add_func("/sexpr/parse-error", test_parse_error);
    return g_test_run();
}
