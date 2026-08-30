/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-ccc.h"

#include "snx-ccc-internal.h"
#include "snx-errors.h"
#include "snx-obfuscate.h"
#include "snx-sexpr-writer.h"
#include "snx-sexpr.h"

#include <gio/gio.h>
#include <stdlib.h>
#include <string.h>

#define SNX_CCC_PORT 443
#define SNX_CCC_TIMEOUT_SECONDS 15

static guint
next_request_id(void)
{
    static gint counter = 1;

    return (guint) g_atomic_int_add(&counter, 1);
}

/* ---- transport ---- */

static gboolean
accept_any_certificate(GTlsConnection *conn, GTlsCertificate *peer_cert, GTlsCertificateFlags errors, gpointer user_data)
{
    (void) conn;
    (void) peer_cert;
    (void) errors;
    (void) user_data;
    return TRUE;
}

static void
on_socket_client_event(GSocketClient *client,
                       GSocketClientEvent event,
                       GSocketConnectable *connectable,
                       GIOStream *connection,
                       gpointer user_data)
{
    gboolean ignore_cert = GPOINTER_TO_INT(user_data);

    (void) client;
    (void) connectable;

    if (event == G_SOCKET_CLIENT_TLS_HANDSHAKING && ignore_cert && G_IS_TLS_CONNECTION(connection))
        g_signal_connect(connection, "accept-certificate", G_CALLBACK(accept_any_certificate), NULL);
}

gboolean
dechunk(const char *data, gsize len, char **out_body, GError **error)
{
    GString *result = g_string_new(NULL);
    gsize pos = 0;

    while (pos < len) {
        const char *line_end = g_strstr_len(data + pos, (gssize) (len - pos), "\r\n");
        char *endptr = NULL;
        gsize chunk_size;

        if (line_end == NULL) {
            g_string_free(result, TRUE);
            g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "malformed chunked HTTP response");
            return FALSE;
        }

        chunk_size = (gsize) strtoul(data + pos, &endptr, 16);
        pos = (gsize) (line_end - data) + 2;

        if (chunk_size == 0)
            break;

        if (pos + chunk_size + 2 > len + 1) {
            g_string_free(result, TRUE);
            g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "truncated chunked HTTP response");
            return FALSE;
        }

        g_string_append_len(result, data + pos, (gssize) chunk_size);
        pos += chunk_size + 2;
    }

    *out_body = g_string_free(result, FALSE);
    return TRUE;
}

gboolean
parse_http_response(GByteArray *raw, char **out_body, GError **error)
{
    const char *data = (const char *) raw->data;
    gsize len = raw->len;
    const char *header_end = g_strstr_len(data, (gssize) len, "\r\n\r\n");
    gsize header_len;
    g_autofree char *headers = NULL;
    g_autofree char *headers_lower = NULL;
    const char *space;
    int status_code = 0;
    gboolean chunked;
    glong content_length = -1;
    const char *content_length_match;
    const char *body_start;
    gsize body_len;

    if (header_end == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "malformed HTTP response: no header terminator");
        return FALSE;
    }

    header_len = (gsize) (header_end - data);
    headers = g_strndup(data, header_len);
    headers_lower = g_ascii_strdown(headers, -1);

    space = strchr(headers, ' ');
    if (space != NULL)
        status_code = atoi(space + 1);

    chunked = strstr(headers_lower, "transfer-encoding: chunked") != NULL;

    content_length_match = strstr(headers_lower, "content-length:");
    if (content_length_match != NULL) {
        gsize offset = (gsize) (content_length_match - headers_lower);

        content_length = strtol(headers + offset + strlen("content-length:"), NULL, 10);
    }

    body_start = header_end + 4;
    body_len = len - header_len - 4;

    if (chunked) {
        if (!dechunk(body_start, body_len, out_body, error))
            return FALSE;
    } else {
        if (content_length >= 0 && (gsize) content_length <= body_len)
            body_len = (gsize) content_length;
        *out_body = g_strndup(body_start, body_len);
    }

    if (status_code < 200 || status_code >= 300) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "gateway returned HTTP status %d", status_code);
        g_clear_pointer(out_body, g_free);
        return FALSE;
    }

    return TRUE;
}

static gboolean
http_post(const char *host, const char *path, const char *body, gboolean ignore_cert, char **out_body, GError **error)
{
    g_autoptr(GSocketClient) client = g_socket_client_new();
    g_autoptr(GSocketConnection) conn = NULL;
    g_autoptr(GError) local_error = NULL;
    GOutputStream *ostream;
    GInputStream *istream;
    GString *request = g_string_new(NULL);
    gsize body_len = strlen(body);
    g_autoptr(GByteArray) response = g_byte_array_new();
    guint8 buf[4096];

    g_socket_client_set_tls(client, TRUE);
    g_socket_client_set_timeout(client, SNX_CCC_TIMEOUT_SECONDS);
    g_signal_connect(client, "event", G_CALLBACK(on_socket_client_event), GINT_TO_POINTER(ignore_cert));

    conn = g_socket_client_connect_to_host(client, host, SNX_CCC_PORT, NULL, &local_error);
    if (conn == NULL) {
        g_string_free(request, TRUE);
        g_propagate_error(error, g_steal_pointer(&local_error));
        return FALSE;
    }

    g_string_append_printf(request,
                           "POST %s HTTP/1.1\r\n"
                           "Host: %s\r\n"
                           "Content-Type: text/plain\r\n"
                           "Content-Length: %" G_GSIZE_FORMAT "\r\n"
                           "Connection: close\r\n"
                           "\r\n",
                           path,
                           host,
                           body_len);
    g_string_append(request, body);

    ostream = g_io_stream_get_output_stream(G_IO_STREAM(conn));
    if (!g_output_stream_write_all(ostream, request->str, request->len, NULL, NULL, &local_error)) {
        g_string_free(request, TRUE);
        g_propagate_error(error, g_steal_pointer(&local_error));
        return FALSE;
    }
    g_string_free(request, TRUE);

    istream = g_io_stream_get_input_stream(G_IO_STREAM(conn));
    for (;;) {
        gssize n = g_input_stream_read(istream, buf, sizeof(buf), NULL, &local_error);

        if (n < 0) {
            /* Many gateways (including real Check Point ones observed in
             * testing) close the TCP connection after "Connection: close"
             * without sending a TLS close_notify alert first. GIO reports
             * that as G_TLS_ERROR_EOF rather than a clean 0-byte read; it is
             * an expected end of response here, not a transport failure. */
            if (g_error_matches(local_error, G_TLS_ERROR, G_TLS_ERROR_EOF)) {
                g_clear_error(&local_error);
                break;
            }
            g_propagate_error(error, g_steal_pointer(&local_error));
            return FALSE;
        }
        if (n == 0)
            break;
        g_byte_array_append(response, buf, (guint) n);
    }

    g_io_stream_close(G_IO_STREAM(conn), NULL, NULL);

    return parse_http_response(response, out_body, error);
}

/* ---- request builders ---- */

static void
add_client_logging_data(SnxWriter *auth_data)
{
    SnxWriter *logging = snx_writer_add_object(auth_data, "client_logging_data", NULL);
    g_autofree char *machine_id = NULL;

    snx_writer_set_string(logging, "os_name", "Linux");

    if (g_file_get_contents("/etc/machine-id", &machine_id, NULL, NULL))
        snx_writer_set_string(logging, "device_id", g_strstrip(machine_id));
}

char *
build_client_hello_request(void)
{
    SnxWriter *root = snx_writer_new_object("CCCclientRequest");
    SnxWriter *header = snx_writer_add_object(root, "RequestHeader", NULL);
    SnxWriter *data = snx_writer_add_object(root, "RequestData", NULL);
    SnxWriter *client_info = snx_writer_add_object(data, "client_info", NULL);
    char *result;

    snx_writer_set_uint(header, "id", next_request_id());
    snx_writer_set_string(header, "type", "ClientHello");

    snx_writer_set_string(client_info, "client_type", "TRAC");
    snx_writer_set_uint(client_info, "client_version", 1);
    snx_writer_set_bool(client_info, "client_support_saml", TRUE);

    result = snx_writer_to_string(root);
    snx_writer_free(root);
    return result;
}

char *
build_auth_request(const char *login_type, const char *username, const char *password)
{
    SnxWriter *root = snx_writer_new_object("CCCclientRequest");
    SnxWriter *header = snx_writer_add_object(root, "RequestHeader", NULL);
    SnxWriter *data = snx_writer_add_object(root, "RequestData", NULL);
    g_autofree char *username_hex = snx_obfuscate((const guint8 *) username, strlen(username));
    g_autofree char *password_hex = snx_obfuscate((const guint8 *) password, strlen(password));
    char *result;

    snx_writer_set_uint(header, "id", next_request_id());
    snx_writer_set_string(header, "type", "UserPass");

    snx_writer_set_string(data, "client_type", "TRAC");
    snx_writer_set_string(data, "username", username_hex);
    snx_writer_set_string(data, "password", password_hex);
    snx_writer_set_string(data, "selectedLoginOption", login_type);
    add_client_logging_data(data);

    result = snx_writer_to_string(root);
    snx_writer_free(root);
    return result;
}

char *
build_challenge_request(const char *session_id, const char *user_input)
{
    SnxWriter *root = snx_writer_new_object("CCCclientRequest");
    SnxWriter *header = snx_writer_add_object(root, "RequestHeader", NULL);
    SnxWriter *data = snx_writer_add_object(root, "RequestData", NULL);
    g_autofree char *user_input_hex = snx_obfuscate((const guint8 *) user_input, strlen(user_input));
    char *result;

    snx_writer_set_uint(header, "id", next_request_id());
    /* "MultiChallange" (sic): matches the real gateway wire value, not a typo of ours. */
    snx_writer_set_string(header, "type", "MultiChallange");
    snx_writer_set_string(header, "session_id", session_id);

    snx_writer_set_string(data, "client_type", "TRAC");
    snx_writer_set_string(data, "auth_session_id", session_id);
    snx_writer_set_string(data, "user_input", user_input_hex);

    result = snx_writer_to_string(root);
    snx_writer_free(root);
    return result;
}

/* ---- response parsing ---- */

static char *
deobfuscate_or_null(const char *hex)
{
    guint8 *data = NULL;
    gsize len = 0;
    char *result;

    if (hex == NULL || !snx_deobfuscate(hex, &data, &len, NULL))
        return NULL;

    result = g_strndup((const char *) data, len);
    g_free(data);
    return result;
}

void
snx_login_option_free(SnxLoginOption *option)
{
    if (option == NULL)
        return;
    g_free(option->id);
    g_free(option->display_name);
    g_free(option);
}

void
snx_gateway_info_free(SnxGatewayInfo *info)
{
    if (info == NULL)
        return;
    g_free(info->server_ip);
    g_free(info->connectivity_type);
    g_free(info->supported_data_tunnel_protocols);
    g_clear_pointer(&info->login_options, g_ptr_array_unref);
    g_free(info);
}

void
snx_auth_result_free(SnxAuthResult *result)
{
    if (result == NULL)
        return;
    g_free(result->authn_status);
    g_free(result->session_id);
    g_free(result->active_key);
    g_free(result->prompt);
    g_free(result->error_message);
    g_free(result->username);
    g_free(result);
}

gboolean
parse_gateway_info(const SnxSexpr *response, SnxGatewayInfo **out_info, GError **error)
{
    const SnxSexpr *response_data = snx_sexpr_get(response, "ResponseData");
    const SnxSexpr *connectivity;
    const SnxSexpr *login_options_list;
    const char *protocol_version_str;
    SnxGatewayInfo *info;

    if (response_data == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "missing ResponseData in gateway-hello reply");
        return FALSE;
    }

    info = g_new0(SnxGatewayInfo, 1);
    info->login_options = g_ptr_array_new_with_free_func((GDestroyNotify) snx_login_option_free);

    protocol_version_str = snx_sexpr_get_string(response_data, "protocol_version:protocol_version");
    if (protocol_version_str != NULL)
        info->protocol_version = (guint) g_ascii_strtoull(protocol_version_str, NULL, 10);

    connectivity = snx_sexpr_get(response_data, "connectivity_info");
    if (connectivity != NULL) {
        const char *tcpt = snx_sexpr_get_string(connectivity, "tcpt_port");
        const char *natt = snx_sexpr_get_string(connectivity, "natt_port");
        const SnxSexpr *protocols = snx_sexpr_get(connectivity, "supported_data_tunnel_protocols");

        info->server_ip = g_strdup(snx_sexpr_get_string(connectivity, "server_ip"));
        info->connectivity_type = g_strdup(snx_sexpr_get_string(connectivity, "connectivity_type"));
        if (tcpt != NULL)
            info->tcpt_port = (guint) g_ascii_strtoull(tcpt, NULL, 10);
        if (natt != NULL)
            info->natt_port = (guint) g_ascii_strtoull(natt, NULL, 10);

        if (protocols != NULL) {
            guint n = snx_sexpr_field_count(protocols);
            GString *joined = g_string_new(NULL);
            guint p;

            for (p = 0; p < n; p++) {
                const char *proto = snx_sexpr_value_string(snx_sexpr_field_value(protocols, p));

                if (proto != NULL) {
                    if (joined->len > 0)
                        g_string_append(joined, ", ");
                    g_string_append(joined, proto);
                }
            }
            info->supported_data_tunnel_protocols = g_string_free(joined, FALSE);
        }
    }

    login_options_list = snx_sexpr_get(response_data, "login_options_data:login_options_list");
    if (login_options_list != NULL) {
        guint count = snx_sexpr_field_count(login_options_list);
        guint i;

        for (i = 0; i < count; i++) {
            const SnxSexpr *option = snx_sexpr_field_value(login_options_list, i);
            const SnxSexpr *factors = snx_sexpr_get(option, "factors");
            guint factor_count = factors != NULL ? snx_sexpr_field_count(factors) : 0;
            SnxLoginOption *parsed = g_new0(SnxLoginOption, 1);
            guint f;

            parsed->id = g_strdup(snx_sexpr_get_string(option, "id"));
            parsed->display_name = g_strdup(snx_sexpr_get_string(option, "display_name"));

            for (f = 0; f < factor_count; f++) {
                const char *factor_type =
                    snx_sexpr_get_string(snx_sexpr_field_value(factors, f), "factor_type");

                if (g_strcmp0(factor_type, "certificate") == 0)
                    parsed->is_certificate = TRUE;
                else
                    parsed->is_multi_factor = TRUE;
            }

            g_ptr_array_add(info->login_options, parsed);
        }
    }

    *out_info = info;
    return TRUE;
}

gboolean
parse_auth_result(const SnxSexpr *response, SnxAuthResult **out_result, GError **error)
{
    const SnxSexpr *response_data = snx_sexpr_get(response, "ResponseData");
    const char *is_authenticated_str;
    SnxAuthResult *result;

    if (response_data == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_PARSE, "missing ResponseData in auth reply");
        return FALSE;
    }

    result = g_new0(SnxAuthResult, 1);
    result->authn_status = g_strdup(snx_sexpr_get_string(response_data, "authn_status"));
    result->session_id = g_strdup(snx_sexpr_get_string(response_data, "session_id"));
    result->username = g_strdup(snx_sexpr_get_string(response_data, "username"));
    result->active_key = deobfuscate_or_null(snx_sexpr_get_string(response_data, "active_key"));
    result->prompt = deobfuscate_or_null(snx_sexpr_get_string(response_data, "prompt"));
    result->error_message = deobfuscate_or_null(snx_sexpr_get_string(response_data, "error_message"));

    is_authenticated_str = snx_sexpr_get_string(response_data, "is_authenticated");
    result->is_authenticated = g_strcmp0(is_authenticated_str, "true") == 0;

    *out_result = result;
    return TRUE;
}

/* ---- public API ---- */

static gboolean
send_ccc_request(const SnxCccOptions *options, const char *request_body, SnxSexpr **out_response, GError **error)
{
    g_autofree char *response_body = NULL;

    if (!http_post(options->server_name, "/clients/", request_body, options->ignore_server_cert, &response_body, error))
        return FALSE;

    *out_response = snx_sexpr_parse(response_body, error);
    return *out_response != NULL;
}

gboolean
snx_ccc_get_gateway_info(const SnxCccOptions *options, SnxGatewayInfo **out_info, GError **error)
{
    g_autofree char *request_body = build_client_hello_request();
    SnxSexpr *response = NULL;
    gboolean ok;

    if (!send_ccc_request(options, request_body, &response, error))
        return FALSE;

    ok = parse_gateway_info(response, out_info, error);
    snx_sexpr_free(response);
    return ok;
}

gboolean
snx_ccc_authenticate(const SnxCccOptions *options,
                     const char *login_type,
                     const char *username,
                     const char *password,
                     SnxAuthResult **out_result,
                     GError **error)
{
    g_autofree char *request_body = build_auth_request(login_type, username, password);
    SnxSexpr *response = NULL;
    gboolean ok;

    if (!send_ccc_request(options, request_body, &response, error))
        return FALSE;

    ok = parse_auth_result(response, out_result, error);
    snx_sexpr_free(response);
    return ok;
}

gboolean
snx_ccc_challenge_code(const SnxCccOptions *options,
                       const char *session_id,
                       const char *user_input,
                       SnxAuthResult **out_result,
                       GError **error)
{
    g_autofree char *request_body = build_challenge_request(session_id, user_input);
    SnxSexpr *response = NULL;
    gboolean ok;

    if (!send_ccc_request(options, request_body, &response, error))
        return FALSE;

    ok = parse_auth_result(response, out_result, error);
    snx_sexpr_free(response);
    return ok;
}
