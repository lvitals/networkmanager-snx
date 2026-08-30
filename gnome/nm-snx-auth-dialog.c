/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-config.h"
#include "snx-service-name.h"

#include <NetworkManager.h>
#include <gtk/gtk.h>
#include <nma-vpn-password-dialog.h>
#include <stdio.h>

typedef struct {
    char *value;
    gboolean should_ask;
    gboolean challenge;
} SnxSecretPrompt;

static gboolean
hash_value_non_empty(GHashTable *table, const char *key)
{
    const char *value = table != NULL ? g_hash_table_lookup(table, key) : NULL;

    return value != NULL && *value != '\0';
}

static gboolean
secret_flag_is_set(GHashTable *data, const char *secret_name, NMSettingSecretFlags flag)
{
    NMSettingSecretFlags flags = NM_SETTING_SECRET_FLAG_NONE;

    if (data == NULL)
        return FALSE;

    if (!nm_vpn_service_plugin_get_secret_flags(data, secret_name, &flags))
        return FALSE;

    return (flags & flag) != 0;
}

static SnxSecretPrompt
determine_password_prompt(const SnxConfig *config, GHashTable *data, GHashTable *secrets, gboolean reprompt)
{
    SnxSecretPrompt prompt = {0};
    gboolean not_required = secret_flag_is_set(data, "password", NM_SETTING_SECRET_FLAG_NOT_REQUIRED);
    gboolean not_saved = secret_flag_is_set(data, "password", NM_SETTING_SECRET_FLAG_NOT_SAVED);

    prompt.value = g_strdup(g_hash_table_lookup(secrets, "password"));
    prompt.should_ask = !not_required && (reprompt || !config->has_password || not_saved);

    return prompt;
}

static SnxSecretPrompt
determine_cert_password_prompt(const SnxConfig *config, GHashTable *data, GHashTable *secrets, gboolean reprompt)
{
    SnxSecretPrompt prompt = {0};
    gboolean has_cert = hash_value_non_empty(data, "cert-path") || hash_value_non_empty(data, "cert-id");
    gboolean not_required = secret_flag_is_set(data, "cert-password", NM_SETTING_SECRET_FLAG_NOT_REQUIRED);
    gboolean not_saved = secret_flag_is_set(data, "cert-password", NM_SETTING_SECRET_FLAG_NOT_SAVED);

    prompt.value = g_strdup(g_hash_table_lookup(secrets, "cert-password"));
    prompt.should_ask = has_cert && !not_required && (reprompt || !config->has_cert_password || not_saved);

    return prompt;
}

static void
add_secret_group(GKeyFile *keyfile, const char *key, const char *label, const SnxSecretPrompt *prompt)
{
    g_key_file_set_string(keyfile, key, "Value", prompt->value != NULL ? prompt->value : "");
    g_key_file_set_string(keyfile, key, "Label", label);
    g_key_file_set_boolean(keyfile, key, "IsSecret", TRUE);
    g_key_file_set_boolean(keyfile, key, "ShouldAsk", prompt->should_ask);
    g_key_file_set_boolean(keyfile, key, "ForceEcho", FALSE);
}

static gboolean
has_hint(char **hints, const char *needle)
{
    if (hints == NULL || needle == NULL)
        return FALSE;

    for (guint i = 0; hints[i] != NULL; i++) {
        if (g_str_equal(hints[i], needle))
            return TRUE;
    }

    return FALSE;
}

static void
write_secrets_keyfile(const char *vpn_name,
                      const SnxSecretPrompt *password_prompt,
                      const SnxSecretPrompt *cert_password_prompt)
{
    g_autoptr(GKeyFile) keyfile = g_key_file_new();
    g_autofree char *description = g_strdup_printf("Authenticate to the SNX VPN connection \"%s\".", vpn_name);
    g_autofree char *data = NULL;

    g_key_file_set_string(keyfile, "VPN Plugin UI", "Version", "2");
    g_key_file_set_string(keyfile, "VPN Plugin UI", "Description", description);
    g_key_file_set_string(keyfile, "VPN Plugin UI", "Title", "Authenticate VPN");

    if (password_prompt->should_ask || (password_prompt->value != NULL && *password_prompt->value != '\0'))
        add_secret_group(keyfile, "password", password_prompt->challenge ? "MFA code" : "Password", password_prompt);

    if (cert_password_prompt->should_ask ||
        (cert_password_prompt->value != NULL && *cert_password_prompt->value != '\0'))
        add_secret_group(keyfile, "cert-password", "Certificate password", cert_password_prompt);

    data = g_key_file_to_data(keyfile, NULL, NULL);
    fputs(data, stdout);
    fflush(stdout);
}

static gboolean
run_interactive_dialog(const char *vpn_name, SnxSecretPrompt *password_prompt, SnxSecretPrompt *cert_password_prompt)
{
    GtkWidget *dialog;
    g_autofree char *message =
        g_strdup_printf(password_prompt->challenge ? "Enter the verification code for \"%s\"."
                                                   : "Enter the password for \"%s\".",
                        vpn_name);
    gboolean accepted;

    gtk_init();

    dialog = nma_vpn_password_dialog_new("Authenticate VPN", message, NULL);
    nma_vpn_password_dialog_set_password_label(NMA_VPN_PASSWORD_DIALOG(dialog),
                                               password_prompt->challenge ? "MFA code:" : "Password:");
    nma_vpn_password_dialog_set_password(NMA_VPN_PASSWORD_DIALOG(dialog), password_prompt->value);

    if (cert_password_prompt->should_ask) {
        nma_vpn_password_dialog_set_show_password_secondary(NMA_VPN_PASSWORD_DIALOG(dialog), TRUE);
        nma_vpn_password_dialog_set_password_secondary_label(NMA_VPN_PASSWORD_DIALOG(dialog),
                                                              "Certificate password:");
        nma_vpn_password_dialog_set_password_secondary(NMA_VPN_PASSWORD_DIALOG(dialog), cert_password_prompt->value);
    }

    gtk_window_present(GTK_WINDOW(dialog));
    accepted = nma_vpn_password_dialog_run_and_block(NMA_VPN_PASSWORD_DIALOG(dialog));
    if (accepted) {
        g_free(password_prompt->value);
        password_prompt->value = g_strdup(nma_vpn_password_dialog_get_password(NMA_VPN_PASSWORD_DIALOG(dialog)));

        if (cert_password_prompt->should_ask) {
            g_free(cert_password_prompt->value);
            cert_password_prompt->value =
                g_strdup(nma_vpn_password_dialog_get_password_secondary(NMA_VPN_PASSWORD_DIALOG(dialog)));
        }
    }

    gtk_window_destroy(GTK_WINDOW(dialog));

    return accepted;
}

int
main(int argc, char **argv)
{
    g_autofree char *vpn_name = NULL;
    g_autofree char *vpn_uuid = NULL;
    g_autofree char *vpn_service = NULL;
    gboolean reprompt = FALSE;
    gboolean allow_interaction = FALSE;
    gboolean external_ui_mode = FALSE;
    g_auto(GStrv) hints = NULL;
    g_autoptr(GOptionContext) context = NULL;
    g_autoptr(GError) error = NULL;
    g_autoptr(GHashTable) data = NULL;
    g_autoptr(GHashTable) secrets = NULL;
    SnxConfig config;
    SnxSecretPrompt password_prompt = {0};
    SnxSecretPrompt cert_password_prompt = {0};
    gboolean need_interaction;

    GOptionEntry options[] = {
        {"name", 'n', 0, G_OPTION_ARG_STRING, &vpn_name, "Name of VPN connection", NULL},
        {"service", 's', 0, G_OPTION_ARG_STRING, &vpn_service, "VPN service type", NULL},
        {"uuid", 'u', 0, G_OPTION_ARG_STRING, &vpn_uuid, "UUID of VPN connection", NULL},
        {"reprompt", 'r', 0, G_OPTION_ARG_NONE, &reprompt, "Reprompt for passwords", NULL},
        {"allow-interaction", 'i', 0, G_OPTION_ARG_NONE, &allow_interaction, "Allow user interaction", NULL},
        {"external-ui-mode", 0, 0, G_OPTION_ARG_NONE, &external_ui_mode, "External UI mode", NULL},
        {"hint", 't', 0, G_OPTION_ARG_STRING_ARRAY, &hints, "Hints from the VPN plugin", NULL},
        G_OPTION_ENTRY_NULL,
    };

    context = g_option_context_new("- SNX VPN auth dialog");
    g_option_context_add_main_entries(context, options, NULL);
    if (!g_option_context_parse(context, &argc, &argv, &error)) {
        g_printerr("Error parsing options: %s\n", error->message);
        return 1;
    }

    if (vpn_name == NULL || vpn_uuid == NULL || vpn_service == NULL) {
        g_printerr("A connection UUID, name, and VPN plugin service name are required.\n");
        return 1;
    }

    if (!g_str_equal(vpn_service, SNX_DBUS_SERVICE_NAME)) {
        g_printerr("This dialog only works with the '%s' service.\n", SNX_DBUS_SERVICE_NAME);
        return 1;
    }

    if (!nm_vpn_service_plugin_read_vpn_details(0, &data, &secrets)) {
        g_printerr("Failed to read '%s' (%s) data and secrets from stdin.\n", vpn_name, vpn_uuid);
        return 1;
    }

    snx_config_init(&config);
    if (!snx_config_apply_hash(&config, data, FALSE, &error) ||
        !snx_config_apply_hash(&config, secrets, TRUE, &error)) {
        g_printerr("Failed to parse connection data: %s\n", error->message);
        snx_config_clear(&config);
        return 1;
    }

    password_prompt = determine_password_prompt(&config, data, secrets, reprompt);
    cert_password_prompt = determine_cert_password_prompt(&config, data, secrets, reprompt);
    password_prompt.challenge = has_hint(hints, "x-snx-challenge");
    snx_config_clear(&config);

    need_interaction = password_prompt.should_ask || cert_password_prompt.should_ask;

    if (need_interaction && !external_ui_mode) {
        if (!allow_interaction) {
            g_printerr("Interaction is not allowed, cannot prompt for secrets.\n");
            g_free(password_prompt.value);
            g_free(cert_password_prompt.value);
            return 1;
        }

        if (!run_interactive_dialog(vpn_name, &password_prompt, &cert_password_prompt)) {
            g_free(password_prompt.value);
            g_free(cert_password_prompt.value);
            return 1;
        }
    }

    write_secrets_keyfile(vpn_name, &password_prompt, &cert_password_prompt);

    g_free(password_prompt.value);
    g_free(cert_password_prompt.value);

    return 0;
}
