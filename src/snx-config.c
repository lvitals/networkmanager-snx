/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-config.h"

#include "snx-errors.h"

#include <ctype.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    SnxConfig *config;
    gboolean secret;
    GError **error;
    gboolean ok;
} ApplyContext;

static void
replace_string(char **target, const char *value)
{
    g_free(*target);
    *target = g_strdup(value != NULL ? value : "");
}

static GPtrArray *
new_string_array(void)
{
    return g_ptr_array_new_with_free_func(g_free);
}

static void
reset_array_from_csv(GPtrArray *array, const char *value)
{
    g_ptr_array_set_size(array, 0);

    if (value == NULL || *value == '\0')
        return;

    char **parts = g_strsplit(value, ",", -1);
    for (guint i = 0; parts[i] != NULL; i++) {
        char *trimmed = g_strstrip(parts[i]);
        if (*trimmed != '\0')
            g_ptr_array_add(array, g_strdup(trimmed));
    }
    g_strfreev(parts);
}

static gboolean
parse_bool(const char *value, gboolean *out, GError **error)
{
    if (value == NULL) {
        *out = FALSE;
        return TRUE;
    }

    if (g_ascii_strcasecmp(value, "true") == 0 || strcmp(value, "1") == 0 ||
        g_ascii_strcasecmp(value, "yes") == 0) {
        *out = TRUE;
        return TRUE;
    }

    if (g_ascii_strcasecmp(value, "false") == 0 || strcmp(value, "0") == 0 ||
        g_ascii_strcasecmp(value, "no") == 0) {
        *out = FALSE;
        return TRUE;
    }

    g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "invalid boolean value: %s", value);
    return FALSE;
}

static gboolean
parse_uint(const char *value, guint *out, GError **error)
{
    char *end = NULL;
    unsigned long parsed;

    if (value == NULL || *value == '\0') {
        *out = 0;
        return TRUE;
    }

    parsed = strtoul(value, &end, 10);
    if (end == value || *end != '\0' || parsed > G_MAXUINT) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "invalid unsigned integer value: %s", value);
        return FALSE;
    }

    *out = (guint) parsed;
    return TRUE;
}

static gboolean
is_supported_choice(const char *value, const char *const *choices)
{
    for (guint i = 0; choices[i] != NULL; i++) {
        if (g_ascii_strcasecmp(value, choices[i]) == 0)
            return TRUE;
    }
    return FALSE;
}

void
snx_config_init(SnxConfig *config)
{
    memset(config, 0, sizeof(*config));

    config->tunnel_type = g_strdup("ipsec");
    config->transport_type = g_strdup("auto");
    config->dns_servers = new_string_array();
    config->ignore_dns_servers = new_string_array();
    config->search_domains = new_string_array();
    config->ignore_search_domains = new_string_array();
    config->add_routes = new_string_array();
    config->ignore_routes = new_string_array();
    config->ca_certs = new_string_array();
    config->password_factor = 1;
    config->ike_lifetime = 28800;
    config->set_routing_domains = TRUE;
    config->mtu = 1300;
    config->dns_priority = -100;
}

void
snx_config_clear(SnxConfig *config)
{
    g_clear_pointer(&config->profile_name, g_free);
    g_clear_pointer(&config->server_name, g_free);
    g_clear_pointer(&config->user_name, g_free);
    g_clear_pointer(&config->login_type, g_free);
    g_clear_pointer(&config->tunnel_type, g_free);
    g_clear_pointer(&config->transport_type, g_free);
    g_clear_pointer(&config->if_name, g_free);
    g_clear_pointer(&config->cert_type, g_free);
    g_clear_pointer(&config->cert_path, g_free);
    g_clear_pointer(&config->cert_id, g_free);
    g_clear_pointer(&config->dns_servers, g_ptr_array_unref);
    g_clear_pointer(&config->ignore_dns_servers, g_ptr_array_unref);
    g_clear_pointer(&config->search_domains, g_ptr_array_unref);
    g_clear_pointer(&config->ignore_search_domains, g_ptr_array_unref);
    g_clear_pointer(&config->add_routes, g_ptr_array_unref);
    g_clear_pointer(&config->ignore_routes, g_ptr_array_unref);
    g_clear_pointer(&config->ca_certs, g_ptr_array_unref);
    memset(config, 0, sizeof(*config));
}

gboolean
snx_config_apply_item(SnxConfig *config, const char *key, const char *value, gboolean secret, GError **error)
{
    static const char *const tunnel_types[] = {"ipsec", "ssl", NULL};
    static const char *const transport_types[] = {"auto", "kernel", "udp", "tcpt", NULL};
    gboolean parsed_bool;
    guint parsed_uint;

    if (key == NULL || *key == '\0')
        return TRUE;

    if (g_str_equal(key, "server") || g_str_equal(key, "server-name")) {
        replace_string(&config->server_name, value);
    } else if (g_str_equal(key, "username") || g_str_equal(key, "user-name")) {
        replace_string(&config->user_name, value);
    } else if (g_str_equal(key, "profile-name")) {
        replace_string(&config->profile_name, value);
    } else if (g_str_equal(key, "login-type")) {
        replace_string(&config->login_type, value);
    } else if (g_str_equal(key, "password")) {
        config->has_password = secret || (value != NULL && *value != '\0');
    } else if (g_str_equal(key, "cert-password")) {
        config->has_cert_password = secret || (value != NULL && *value != '\0');
    } else if (g_str_equal(key, "password-factor")) {
        if (!parse_uint(value, &parsed_uint, error))
            return FALSE;
        config->password_factor = parsed_uint > 0 ? parsed_uint : 1;
    } else if (g_str_equal(key, "tunnel-type")) {
        if (!is_supported_choice(value, tunnel_types)) {
            g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "invalid tunnel-type: %s", value);
            return FALSE;
        }
        replace_string(&config->tunnel_type, value);
    } else if (g_str_equal(key, "transport-type")) {
        if (!is_supported_choice(value, transport_types)) {
            g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "invalid transport-type: %s", value);
            return FALSE;
        }
        replace_string(&config->transport_type, value);
    } else if (g_str_equal(key, "if-name")) {
        replace_string(&config->if_name, value);
    } else if (g_str_equal(key, "cert-type")) {
        replace_string(&config->cert_type, value);
    } else if (g_str_equal(key, "cert-path")) {
        replace_string(&config->cert_path, value);
    } else if (g_str_equal(key, "cert-id")) {
        replace_string(&config->cert_id, value);
    } else if (g_str_equal(key, "dns-servers")) {
        reset_array_from_csv(config->dns_servers, value);
    } else if (g_str_equal(key, "ignore-dns-servers")) {
        reset_array_from_csv(config->ignore_dns_servers, value);
    } else if (g_str_equal(key, "search-domains")) {
        reset_array_from_csv(config->search_domains, value);
    } else if (g_str_equal(key, "ignore-search-domains")) {
        reset_array_from_csv(config->ignore_search_domains, value);
    } else if (g_str_equal(key, "add-routes")) {
        reset_array_from_csv(config->add_routes, value);
    } else if (g_str_equal(key, "ignore-routes")) {
        reset_array_from_csv(config->ignore_routes, value);
    } else if (g_str_equal(key, "ca-cert")) {
        reset_array_from_csv(config->ca_certs, value);
    } else if (g_str_equal(key, "default-route")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->default_route = parsed_bool;
    } else if (g_str_equal(key, "no-routing")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->no_routing = parsed_bool;
    } else if (g_str_equal(key, "ignore-server-cert")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->ignore_server_cert = parsed_bool;
    } else if (g_str_equal(key, "no-keepalive")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->no_keepalive = parsed_bool;
    } else if (g_str_equal(key, "port-knock")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->port_knock = parsed_bool;
    } else if (g_str_equal(key, "ike-persist")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->ike_persist = parsed_bool;
    } else if (g_str_equal(key, "set-routing-domains")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->set_routing_domains = parsed_bool;
    } else if (g_str_equal(key, "disable-ipv6")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->disable_ipv6 = parsed_bool;
    } else if (g_str_equal(key, "allow-forwarding")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->allow_forwarding = parsed_bool;
    } else if (g_str_equal(key, "keychain")) {
        if (!parse_bool(value, &parsed_bool, error))
            return FALSE;
        config->keychain = parsed_bool;
    } else if (g_str_equal(key, "ike-lifetime")) {
        if (!parse_uint(value, &parsed_uint, error))
            return FALSE;
        config->ike_lifetime = parsed_uint;
    } else if (g_str_equal(key, "ip-lease-time")) {
        if (!parse_uint(value, &parsed_uint, error))
            return FALSE;
        config->ip_lease_time = parsed_uint;
    } else if (g_str_equal(key, "mtu")) {
        if (!parse_uint(value, &parsed_uint, error))
            return FALSE;
        config->mtu = parsed_uint;
    } else if (g_str_equal(key, "dns-priority")) {
        config->dns_priority = (gint) g_ascii_strtoll(value, NULL, 10);
    }

    return TRUE;
}

static void
apply_hash_item(gpointer key, gpointer value, gpointer user_data)
{
    ApplyContext *ctx = user_data;

    if (!ctx->ok)
        return;

    ctx->ok = snx_config_apply_item(ctx->config, key, value, ctx->secret, ctx->error);
}

gboolean
snx_config_apply_hash(SnxConfig *config, GHashTable *items, gboolean secret, GError **error)
{
    ApplyContext ctx = {
        .config = config,
        .secret = secret,
        .error = error,
        .ok = TRUE,
    };

    if (items == NULL)
        return TRUE;

    g_hash_table_foreach(items, apply_hash_item, &ctx);
    return ctx.ok;
}

static void
apply_nm_data_item(const char *key, const char *value, gpointer user_data)
{
    ApplyContext *ctx = user_data;

    if (!ctx->ok)
        return;

    ctx->ok = snx_config_apply_item(ctx->config, key, value, ctx->secret, ctx->error);
}

gboolean
snx_config_from_connection(SnxConfig *config, NMConnection *connection, GError **error)
{
    NMSettingConnection *s_con;
    NMSettingVpn *s_vpn;
    const char *id;
    const char *uuid;
    const char *user_name;
    ApplyContext ctx;

    g_return_val_if_fail(NM_IS_CONNECTION(connection), FALSE);

    s_con = nm_connection_get_setting_connection(connection);
    if (s_con != NULL) {
        id = nm_setting_connection_get_id(s_con);
        uuid = nm_setting_connection_get_uuid(s_con);
        if (id != NULL)
            replace_string(&config->profile_name, id);
        if (config->if_name == NULL)
            config->if_name = snx_config_default_if_name(id, uuid);
    }

    s_vpn = nm_connection_get_setting_vpn(connection);
    if (s_vpn == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "missing vpn setting");
        return FALSE;
    }

    user_name = nm_setting_vpn_get_user_name(s_vpn);
    if (user_name != NULL && *user_name != '\0')
        replace_string(&config->user_name, user_name);

    ctx.config = config;
    ctx.secret = FALSE;
    ctx.error = error;
    ctx.ok = TRUE;
    nm_setting_vpn_foreach_data_item(s_vpn, apply_nm_data_item, &ctx);
    if (!ctx.ok)
        return FALSE;

    ctx.secret = TRUE;
    nm_setting_vpn_foreach_secret(s_vpn, apply_nm_data_item, &ctx);
    return ctx.ok;
}

gboolean
snx_config_validate_for_connect(const SnxConfig *config, GError **error)
{
    if (config->server_name == NULL || *config->server_name == '\0') {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "server-name is required");
        return FALSE;
    }

    if (config->login_type == NULL || *config->login_type == '\0') {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "login-type is required");
        return FALSE;
    }

    return TRUE;
}

gboolean
snx_config_needs_password(const SnxConfig *config)
{
    if (config->user_name == NULL || *config->user_name == '\0')
        return TRUE;

    return !config->has_password;
}

char *
snx_config_default_if_name(const char *connection_id, const char *uuid)
{
    (void) connection_id;
    (void) uuid;

    return g_strdup("snx-tun");
}
