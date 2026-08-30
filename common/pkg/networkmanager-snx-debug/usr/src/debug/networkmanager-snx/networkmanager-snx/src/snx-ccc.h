/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_CCC_H
#define SNX_CCC_H

#include <glib.h>

/*
 * Client to Client Communication (CCC): the HTTPS/S-expression protocol
 * Check Point gateways use for gateway discovery, login-method discovery,
 * and username/password authentication. This does not establish a data
 * tunnel; it only gets as far as a session id.
 */

typedef struct {
    char *server_name;
    gboolean ignore_server_cert;
} SnxCccOptions;

typedef struct {
    char *id;
    char *display_name;
    gboolean is_certificate;
    gboolean is_multi_factor;
} SnxLoginOption;

void snx_login_option_free(SnxLoginOption *option);

typedef struct {
    guint protocol_version;
    char *server_ip;
    char *connectivity_type;
    char *supported_data_tunnel_protocols;
    guint tcpt_port;
    guint natt_port;
    GPtrArray *login_options; /* element-type SnxLoginOption* */
} SnxGatewayInfo;

void snx_gateway_info_free(SnxGatewayInfo *info);

typedef struct {
    char *authn_status;
    gboolean is_authenticated;
    char *session_id;
    char *active_key;
    char *prompt;
    char *error_message;
    char *username;
} SnxAuthResult;

void snx_auth_result_free(SnxAuthResult *result);

gboolean snx_ccc_get_gateway_info(const SnxCccOptions *options, SnxGatewayInfo **out_info, GError **error);

gboolean snx_ccc_authenticate(const SnxCccOptions *options,
                              const char *login_type,
                              const char *username,
                              const char *password,
                              SnxAuthResult **out_result,
                              GError **error);

gboolean snx_ccc_challenge_code(const SnxCccOptions *options,
                                const char *session_id,
                                const char *user_input,
                                SnxAuthResult **out_result,
                                GError **error);

#endif
