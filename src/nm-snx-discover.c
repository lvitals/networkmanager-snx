/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-ccc.h"

#include <glib.h>
#include <stdio.h>

int
main(int argc, char **argv)
{
    gboolean insecure = FALSE;
    g_autofree char *server_name = NULL;
    GOptionEntry options[] = {
        {"insecure", 'k', 0, G_OPTION_ARG_NONE, &insecure, "Do not validate the gateway's TLS certificate", NULL},
        G_OPTION_ENTRY_NULL,
    };
    g_autoptr(GOptionContext) context = g_option_context_new("SERVER-NAME");
    g_autoptr(GError) error = NULL;
    SnxCccOptions ccc_options = {0};
    SnxGatewayInfo *info = NULL;
    guint i;

    g_option_context_add_main_entries(context, options, NULL);
    g_option_context_set_summary(context,
                                 "Reads a Check Point gateway's connectivity information and the list of\n"
                                 "real login-type ids it offers, via a read-only CCC ClientHello request.\n"
                                 "No credentials are sent and no session is created.");
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr("Error parsing options: %s\n", error->message);
        return 1;
    }

    if (argc != 2) {
        g_printerr("%s", g_option_context_get_help(context, TRUE, NULL));
        return 1;
    }
    server_name = g_strdup(argv[1]);

    ccc_options.server_name = server_name;
    ccc_options.ignore_server_cert = insecure;

    if (!snx_ccc_get_gateway_info(&ccc_options, &info, &error)) {
        g_printerr("Failed to contact %s: %s\n", server_name, error->message);
        return 1;
    }

    g_print("Gateway: %s\n", server_name);
    g_print("Protocol version: %u\n", info->protocol_version);
    g_print("Server IP: %s\n", info->server_ip != NULL ? info->server_ip : "(unknown)");
    g_print("Preferred connectivity: %s\n",
           info->connectivity_type != NULL ? info->connectivity_type : "(unknown)");
    g_print("Supported tunnel protocols: %s\n",
           info->supported_data_tunnel_protocols != NULL ? info->supported_data_tunnel_protocols : "(unknown)");
    g_print("NAT-T port: %u   TCPT port: %u\n\n", info->natt_port, info->tcpt_port);

    if (info->login_options->len == 0) {
        g_print("No login methods advertised by this gateway.\n");
    } else {
        g_print("Login methods (use the id, not the display name, as login-type):\n");
        for (i = 0; i < info->login_options->len; i++) {
            SnxLoginOption *option = g_ptr_array_index(info->login_options, i);

            g_print("  login-type=%-28s  \"%s\"%s%s\n",
                   option->id,
                   option->display_name,
                   option->is_certificate ? "  [certificate]" : "",
                   option->is_multi_factor ? "  [password/MFA]" : "");
        }
    }

    snx_gateway_info_free(info);
    return 0;
}
