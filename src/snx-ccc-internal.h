/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_CCC_INTERNAL_H
#define SNX_CCC_INTERNAL_H

/* Internals of snx-ccc.c exposed only so tests can exercise HTTP/S-expression
 * parsing and request building without a live network connection. Not part
 * of the public snx-ccc.h API. */

#include "snx-ccc.h"
#include "snx-sexpr.h"

#include <glib.h>

gboolean dechunk(const char *data, gsize len, char **out_body, GError **error);
gboolean parse_http_response(GByteArray *raw, char **out_body, GError **error);

char *build_client_hello_request(void);
char *build_auth_request(const char *login_type, const char *username, const char *password);
char *build_challenge_request(const char *session_id, const char *user_input);

gboolean parse_gateway_info(const SnxSexpr *response, SnxGatewayInfo **out_info, GError **error);
gboolean parse_auth_result(const SnxSexpr *response, SnxAuthResult **out_result, GError **error);

#endif
