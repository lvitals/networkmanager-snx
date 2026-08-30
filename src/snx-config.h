/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_CONFIG_H
#define SNX_CONFIG_H

#include <NetworkManager.h>
#include <glib.h>

typedef struct {
    char *profile_name;
    char *server_name;
    char *user_name;
    char *login_type;
    char *tunnel_type;
    char *transport_type;
    char *if_name;
    char *cert_type;
    char *cert_path;
    char *cert_id;
    GPtrArray *dns_servers;
    GPtrArray *ignore_dns_servers;
    GPtrArray *search_domains;
    GPtrArray *ignore_search_domains;
    GPtrArray *add_routes;
    GPtrArray *ignore_routes;
    GPtrArray *ca_certs;
    gboolean default_route;
    gboolean no_routing;
    gboolean ignore_server_cert;
    gboolean no_keepalive;
    gboolean port_knock;
    gboolean ike_persist;
    gboolean set_routing_domains;
    gboolean disable_ipv6;
    gboolean allow_forwarding;
    gboolean keychain;
    gboolean has_password;
    gboolean has_cert_password;
    guint password_factor;
    guint ike_lifetime;
    guint ip_lease_time;
    guint mtu;
    gint dns_priority;
} SnxConfig;

void snx_config_init(SnxConfig *config);
void snx_config_clear(SnxConfig *config);

gboolean snx_config_apply_item(SnxConfig *config,
                               const char *key,
                               const char *value,
                               gboolean secret,
                               GError **error);
gboolean snx_config_apply_hash(SnxConfig *config, GHashTable *items, gboolean secret, GError **error);
gboolean snx_config_from_connection(SnxConfig *config, NMConnection *connection, GError **error);
gboolean snx_config_validate_for_connect(const SnxConfig *config, GError **error);
gboolean snx_config_needs_password(const SnxConfig *config);
char *snx_config_default_if_name(const char *connection_id, const char *uuid);

#endif
