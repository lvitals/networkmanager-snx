/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-ccc-internal.h"
#include "snx-errors.h"
#include "snx-obfuscate.h"

#include <glib.h>
#include <string.h>

static void
test_dechunk_simple(void)
{
    const char *chunked = "5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
    g_autoptr(GError) error = NULL;
    g_autofree char *body = NULL;

    g_assert_true(dechunk(chunked, strlen(chunked), &body, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(body, ==, "hello world");
}

static void
test_dechunk_malformed(void)
{
    const char *chunked = "not-a-chunk-size-line-without-crlf";
    g_autoptr(GError) error = NULL;
    char *body = NULL;

    g_assert_false(dechunk(chunked, strlen(chunked), &body, &error));
    g_assert_error(error, SNX_ERROR, SNX_ERROR_PARSE);
}

static GByteArray *
bytes_from_string(const char *s)
{
    GByteArray *array = g_byte_array_new();

    g_byte_array_append(array, (const guint8 *) s, (guint) strlen(s));
    return array;
}

static void
test_parse_http_response_content_length(void)
{
    g_autoptr(GByteArray) raw =
        bytes_from_string("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello");
    g_autoptr(GError) error = NULL;
    g_autofree char *body = NULL;

    g_assert_true(parse_http_response(raw, &body, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(body, ==, "hello");
}

static void
test_parse_http_response_chunked(void)
{
    g_autoptr(GByteArray) raw = bytes_from_string(
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\ntest\r\n0\r\n\r\n");
    g_autoptr(GError) error = NULL;
    g_autofree char *body = NULL;

    g_assert_true(parse_http_response(raw, &body, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(body, ==, "test");
}

static void
test_parse_http_response_error_status(void)
{
    g_autoptr(GByteArray) raw = bytes_from_string("HTTP/1.1 500 Internal Server Error\r\n\r\noops");
    g_autoptr(GError) error = NULL;
    char *body = NULL;

    g_assert_false(parse_http_response(raw, &body, &error));
    g_assert_error(error, SNX_ERROR, SNX_ERROR_PARSE);
}

static void
test_build_client_hello_request(void)
{
    g_autofree char *body = build_client_hello_request();

    g_assert_nonnull(strstr(body, "CCCclientRequest"));
    g_assert_nonnull(strstr(body, ":type (ClientHello)"));
    g_assert_nonnull(strstr(body, ":client_type (TRAC)"));
    g_assert_nonnull(strstr(body, ":client_support_saml (true)"));
}

static void
test_build_auth_request_obfuscates_credentials(void)
{
    g_autofree char *body = build_auth_request("PMC", "user@corp.example.com", "s3cr3t");

    g_assert_nonnull(strstr(body, ":type (UserPass)"));
    g_assert_nonnull(strstr(body, ":selectedLoginOption (PMC)"));
    /* Credentials must never appear in the clear in the request body. */
    g_assert_null(strstr(body, "user@corp.example.com"));
    g_assert_null(strstr(body, "s3cr3t"));
}

static void
test_parse_gateway_info(void)
{
    const char *reply = "(CCCserverResponse\n"
                        "\t:ResponseHeader (\n"
                        "\t\t:id (1)\n"
                        "\t\t:type (ClientHello)\n"
                        "\t\t:session_id ()\n"
                        "\t\t:return_code (0))\n"
                        "\t:ResponseData (\n"
                        "\t\t:protocol_version (\n"
                        "\t\t\t:protocol_version (100))\n"
                        "\t\t:connectivity_info (\n"
                        "\t\t\t:client_enabled (true)\n"
                        "\t\t\t:connectivity_type (TRAC)\n"
                        "\t\t\t:server_ip (1.2.3.4)\n"
                        "\t\t\t:tcpt_port (443)\n"
                        "\t\t\t:natt_port (4500))\n"
                        "\t\t:login_options_data (\n"
                        "\t\t\t:login_options_list (\n"
                        "\t\t\t\t:PMC (\n"
                        "\t\t\t\t\t:id (PMC)\n"
                        "\t\t\t\t\t:display_name (\"PMC\")\n"
                        "\t\t\t\t\t:show_realm (1)\n"
                        "\t\t\t\t\t:factors (\n"
                        "\t\t\t\t\t\t:1 (\n"
                        "\t\t\t\t\t\t\t:factor_type (password))))))))";
    g_autoptr(GError) error = NULL;
    SnxSexpr *response;
    SnxGatewayInfo *info = NULL;
    SnxLoginOption *option;

    response = snx_sexpr_parse(reply, &error);
    g_assert_no_error(error);
    g_assert_nonnull(response);

    g_assert_true(parse_gateway_info(response, &info, &error));
    g_assert_no_error(error);
    g_assert_nonnull(info);

    g_assert_cmpuint(info->protocol_version, ==, 100);
    g_assert_cmpstr(info->server_ip, ==, "1.2.3.4");
    g_assert_cmpuint(info->tcpt_port, ==, 443);
    g_assert_cmpuint(info->natt_port, ==, 4500);
    g_assert_cmpuint(info->login_options->len, ==, 1);

    option = g_ptr_array_index(info->login_options, 0);
    g_assert_cmpstr(option->id, ==, "PMC");
    g_assert_cmpstr(option->display_name, ==, "PMC");
    g_assert_false(option->is_certificate);
    g_assert_true(option->is_multi_factor);

    snx_gateway_info_free(info);
    snx_sexpr_free(response);
}

static void
test_parse_auth_result_done(void)
{
    const char *reply = "(CCCserverResponse\n"
                        "\t:ResponseHeader (:return_code (0))\n"
                        "\t:ResponseData (\n"
                        "\t\t:authn_status (done)\n"
                        "\t\t:is_authenticated (true)\n"
                        "\t\t:session_id (\"abc123\")\n"
                        "\t\t:username (user)))";
    g_autoptr(GError) error = NULL;
    SnxSexpr *response;
    SnxAuthResult *result = NULL;

    response = snx_sexpr_parse(reply, &error);
    g_assert_no_error(error);
    g_assert_nonnull(response);

    g_assert_true(parse_auth_result(response, &result, &error));
    g_assert_no_error(error);
    g_assert_nonnull(result);

    g_assert_cmpstr(result->authn_status, ==, "done");
    g_assert_true(result->is_authenticated);
    g_assert_cmpstr(result->session_id, ==, "abc123");
    g_assert_cmpstr(result->username, ==, "user");

    snx_auth_result_free(result);
    snx_sexpr_free(response);
}

static void
test_parse_auth_result_deobfuscates_error_message(void)
{
    g_autofree char *error_hex = snx_obfuscate((const guint8 *) "Invalid credentials", strlen("Invalid credentials"));
    g_autoptr(GError) error = NULL;
    SnxSexpr *response;
    SnxAuthResult *result = NULL;
    g_autofree char *reply = NULL;

    reply = g_strdup_printf("(CCCserverResponse\n"
                            "\t:ResponseHeader (:return_code (0))\n"
                            "\t:ResponseData (\n"
                            "\t\t:authn_status (done)\n"
                            "\t\t:is_authenticated (false)\n"
                            "\t\t:error_message (\"%s\")))",
                            error_hex);

    response = snx_sexpr_parse(reply, &error);
    g_assert_no_error(error);
    g_assert_nonnull(response);

    g_assert_true(parse_auth_result(response, &result, &error));
    g_assert_no_error(error);
    g_assert_nonnull(result);

    g_assert_false(result->is_authenticated);
    g_assert_cmpstr(result->error_message, ==, "Invalid credentials");

    snx_auth_result_free(result);
    snx_sexpr_free(response);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ccc/dechunk-simple", test_dechunk_simple);
    g_test_add_func("/ccc/dechunk-malformed", test_dechunk_malformed);
    g_test_add_func("/ccc/parse-http-response-content-length", test_parse_http_response_content_length);
    g_test_add_func("/ccc/parse-http-response-chunked", test_parse_http_response_chunked);
    g_test_add_func("/ccc/parse-http-response-error-status", test_parse_http_response_error_status);
    g_test_add_func("/ccc/build-client-hello-request", test_build_client_hello_request);
    g_test_add_func("/ccc/build-auth-request-obfuscates-credentials", test_build_auth_request_obfuscates_credentials);
    g_test_add_func("/ccc/parse-gateway-info", test_parse_gateway_info);
    g_test_add_func("/ccc/parse-auth-result-done", test_parse_auth_result_done);
    g_test_add_func("/ccc/parse-auth-result-deobfuscates-error-message", test_parse_auth_result_deobfuscates_error_message);
    return g_test_run();
}
