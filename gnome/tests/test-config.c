/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-config.h"
#include "snx-errors.h"
#include "snx-service-name.h"

#include <NetworkManager.h>
#include <glib.h>

static void
test_apply_items(void)
{
    SnxConfig config;
    g_autoptr(GError) error = NULL;

    snx_config_init(&config);

    g_assert_true(snx_config_apply_item(&config, "server-name", "vpn.example.com", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "user-name", "user@example.com", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "login-type", "vpn_password", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "password", "secret", TRUE, &error));
    g_assert_true(snx_config_apply_item(&config, "tunnel-type", "ipsec", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "transport-type", "udp", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "search-domains", "corp.example.com, example.com", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "cert-type", "pkcs12", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "cert-path", "/home/user/.cert/client.p12", FALSE, &error));
    g_assert_true(snx_config_apply_item(&config, "cert-id", "slot0-token", FALSE, &error));

    g_assert_cmpstr(config.server_name, ==, "vpn.example.com");
    g_assert_cmpstr(config.user_name, ==, "user@example.com");
    g_assert_cmpstr(config.login_type, ==, "vpn_password");
    g_assert_cmpstr(config.transport_type, ==, "udp");
    g_assert_true(config.has_password);
    g_assert_cmpuint(config.search_domains->len, ==, 2);
    g_assert_cmpstr(config.cert_type, ==, "pkcs12");
    g_assert_cmpstr(config.cert_path, ==, "/home/user/.cert/client.p12");
    g_assert_cmpstr(config.cert_id, ==, "slot0-token");
    g_assert_true(snx_config_validate_for_connect(&config, &error));
    g_assert_no_error(error);

    snx_config_clear(&config);
}

static void
test_default_if_name(void)
{
    g_autofree char *name = snx_config_default_if_name("Corporate VPN", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");

    g_assert_cmpstr(name, ==, "snx-tun");
    g_assert_cmpuint(strlen(name), <, 16);
}

static void
test_default_mtu(void)
{
    SnxConfig config;

    snx_config_init(&config);
    g_assert_cmpuint(config.mtu, ==, 1300);
    snx_config_clear(&config);
}

static void
test_connection_option_round_trip(void)
{
    SnxConfig config;
    g_autoptr(NMConnection) connection = nm_simple_connection_new();
    NMSettingConnection *s_con = NM_SETTING_CONNECTION(nm_setting_connection_new());
    NMSettingVpn *s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
    g_autoptr(GError) error = NULL;

    g_object_set(s_con,
                 NM_SETTING_CONNECTION_ID,
                 "SNX Test",
                 NM_SETTING_CONNECTION_UUID,
                 "11111111-1111-1111-1111-111111111111",
                 NM_SETTING_CONNECTION_TYPE,
                 NM_SETTING_VPN_SETTING_NAME,
                 NULL);
    nm_connection_add_setting(connection, NM_SETTING(s_con));

    g_object_set(s_vpn,
                 NM_SETTING_VPN_SERVICE_TYPE,
                 SNX_DBUS_SERVICE_NAME,
                 NM_SETTING_VPN_USER_NAME,
                 "user@example.com",
                 NULL);
    nm_setting_vpn_add_data_item(s_vpn, "server-name", "vpn.example.com");
    nm_setting_vpn_add_data_item(s_vpn, "login-type", "vpn_password");
    nm_setting_vpn_add_data_item(s_vpn, "tunnel-type", "ssl");
    nm_setting_vpn_add_data_item(s_vpn, "transport-type", "tcpt");
    nm_setting_vpn_add_data_item(s_vpn, "if-name", "snx-tun");
    nm_setting_vpn_add_data_item(s_vpn, "mtu", "1300");
    nm_setting_vpn_add_data_item(s_vpn, "default-route", "false");
    nm_setting_vpn_add_data_item(s_vpn, "no-routing", "false");
    nm_setting_vpn_add_data_item(s_vpn, "add-routes", "172.20.0.0/16,10.10.0.0/16");
    nm_setting_vpn_add_data_item(s_vpn, "dns-servers", "172.20.0.198");
    nm_setting_vpn_add_data_item(s_vpn, "search-domains", "corp.example.com");
    nm_setting_vpn_add_data_item(s_vpn, "set-routing-domains", "true");
    nm_setting_vpn_add_data_item(s_vpn, "dns-priority", "-100");
    nm_setting_vpn_add_data_item(s_vpn, "no-keepalive", "true");
    nm_setting_vpn_add_secret(s_vpn, "password", "secret");
    nm_connection_add_setting(connection, NM_SETTING(s_vpn));

    snx_config_init(&config);
    g_assert_true(snx_config_from_connection(&config, connection, &error));
    g_assert_no_error(error);

    g_assert_cmpstr(config.profile_name, ==, "SNX Test");
    g_assert_cmpstr(config.server_name, ==, "vpn.example.com");
    g_assert_cmpstr(config.user_name, ==, "user@example.com");
    g_assert_cmpstr(config.login_type, ==, "vpn_password");
    g_assert_cmpstr(config.tunnel_type, ==, "ssl");
    g_assert_cmpstr(config.transport_type, ==, "tcpt");
    g_assert_cmpstr(config.if_name, ==, "snx-tun");
    g_assert_cmpuint(config.mtu, ==, 1300);
    g_assert_false(config.default_route);
    g_assert_false(config.no_routing);
    g_assert_true(config.set_routing_domains);
    g_assert_true(config.no_keepalive);
    g_assert_true(config.has_password);
    g_assert_cmpint(config.dns_priority, ==, -100);
    g_assert_cmpuint(config.add_routes->len, ==, 2);
    g_assert_cmpstr(g_ptr_array_index(config.add_routes, 0), ==, "172.20.0.0/16");
    g_assert_cmpstr(g_ptr_array_index(config.add_routes, 1), ==, "10.10.0.0/16");
    g_assert_cmpuint(config.dns_servers->len, ==, 1);
    g_assert_cmpstr(g_ptr_array_index(config.dns_servers, 0), ==, "172.20.0.198");
    g_assert_cmpuint(config.search_domains->len, ==, 1);
    g_assert_cmpstr(g_ptr_array_index(config.search_domains, 0), ==, "corp.example.com");

    snx_config_clear(&config);
}

static void
test_invalid_choice(void)
{
    SnxConfig config;
    g_autoptr(GError) error = NULL;

    snx_config_init(&config);
    g_assert_false(snx_config_apply_item(&config, "tunnel-type", "wireguard", FALSE, &error));
    g_assert_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG);
    snx_config_clear(&config);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/config/apply-items", test_apply_items);
    g_test_add_func("/config/default-if-name", test_default_if_name);
    g_test_add_func("/config/default-mtu", test_default_mtu);
    g_test_add_func("/config/connection-option-round-trip", test_connection_option_round_trip);
    g_test_add_func("/config/invalid-choice", test_invalid_choice);
    return g_test_run();
}
