/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-ip4-config.h"
#include "snx-errors.h"

#include <NetworkManager.h>
#include <arpa/inet.h>
#include <glib.h>

static void
test_domain_normalization(void)
{
    g_autofree char *domain = snx_normalize_routing_domain(" example.com ");
    g_autofree char *already_routed = snx_normalize_routing_domain("~corp.example.com");
    g_autofree char *wildcard = snx_normalize_routing_domain("~.");

    g_assert_cmpstr(domain, ==, "~example.com");
    g_assert_cmpstr(already_routed, ==, "~corp.example.com");
    g_assert_null(wildcard);
}

static void
test_ipv4_conversion(void)
{
    guint32 value = 0;
    g_autoptr(GError) error = NULL;

    g_assert_true(snx_ipv4_to_nm_u32("10.200.15.1", &value, &error));
    g_assert_cmphex(value, ==, 0x010fc80a);
    g_assert_no_error(error);
}

static void
test_ip4_config_variant(void)
{
    g_autoptr(GPtrArray) route_specs = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GPtrArray) routes = NULL;
    g_autoptr(GPtrArray) dns = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GPtrArray) domains = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GVariant) variant = NULL;
    g_autoptr(GVariant) routes_variant = NULL;
    g_autoptr(GVariant) dns_variant = NULL;
    g_autoptr(GVariant) domains_variant = NULL;
    g_autoptr(GError) error = NULL;
    guint32 prefix = 0;
    gint32 dns_priority = 0;
    gboolean never_default = FALSE;

    g_ptr_array_add(route_specs, g_strdup("192.0.2.42/24"));
    g_ptr_array_add(dns, g_strdup("172.20.0.198"));
    g_ptr_array_add(domains, g_strdup("example.com"));

    routes = snx_ip4_routes_from_strings(route_specs, &error);
    g_assert_no_error(error);
    g_assert_nonnull(routes);

    variant = snx_ip4_config_new("10.200.15.1", 20, routes, dns, domains, TRUE, -100, TRUE, &error);
    g_assert_no_error(error);
    g_assert_nonnull(variant);
    g_assert_true(g_variant_lookup(variant, "prefix", "u", &prefix));
    g_assert_true(g_variant_lookup(variant, "never-default", "b", &never_default));
    g_assert_true(g_variant_lookup(variant, "dns-priority", "i", &dns_priority));
    g_assert_cmpuint(prefix, ==, 20);
    g_assert_true(never_default);
    g_assert_cmpint(dns_priority, ==, -100);

    routes_variant = g_variant_lookup_value(variant, "routes", NULL);
    dns_variant = g_variant_lookup_value(variant, "dns", G_VARIANT_TYPE("au"));
    domains_variant = g_variant_lookup_value(variant, "domains", G_VARIANT_TYPE("as"));
    g_assert_nonnull(routes_variant);
    g_assert_nonnull(dns_variant);
    g_assert_nonnull(domains_variant);
    g_assert_cmpuint(g_variant_n_children(routes_variant), ==, 1);
    g_assert_cmpuint(g_variant_n_children(dns_variant), ==, 1);
    g_assert_cmpuint(g_variant_n_children(domains_variant), ==, 1);
}

static void
test_ip4_config_non_routing_domain(void)
{
    g_autoptr(GPtrArray) dns = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GPtrArray) domains = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GVariant) variant = NULL;
    g_autoptr(GVariant) domains_variant = NULL;
    g_autoptr(GError) error = NULL;
    const char *domain = NULL;

    g_ptr_array_add(dns, g_strdup("172.20.0.198"));
    g_ptr_array_add(domains, g_strdup("example.com."));

    variant = snx_ip4_config_new("10.200.15.1", 20, NULL, dns, domains, TRUE, -100, FALSE, &error);
    g_assert_no_error(error);
    g_assert_nonnull(variant);

    domains_variant = g_variant_lookup_value(variant, "domains", G_VARIANT_TYPE("as"));
    g_assert_nonnull(domains_variant);
    g_variant_get_child(domains_variant, 0, "&s", &domain);
    g_assert_cmpstr(domain, ==, "example.com");
}

static void
test_route_conversion(void)
{
    g_autoptr(GPtrArray) route_specs = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GPtrArray) routes = NULL;
    g_autoptr(GVariant) variant = NULL;
    g_autoptr(GPtrArray) decoded = NULL;
    g_autoptr(GError) error = NULL;
    NMIPRoute *route;

    g_ptr_array_add(route_specs, g_strdup("192.0.2.42/24"));
    g_ptr_array_add(route_specs, g_strdup("198.51.100.0/25"));

    routes = snx_ip4_routes_from_strings(route_specs, &error);
    g_assert_no_error(error);
    g_assert_nonnull(routes);
    g_assert_cmpuint(routes->len, ==, 2);

    route = g_ptr_array_index(routes, 0);
    g_assert_cmpstr(nm_ip_route_get_dest(route), ==, "192.0.2.0");
    g_assert_cmpuint(nm_ip_route_get_prefix(route), ==, 24);
    g_assert_null(nm_ip_route_get_next_hop(route));

    variant = nm_utils_ip4_routes_to_variant(routes);
    decoded = nm_utils_ip4_routes_from_variant(variant);
    g_assert_cmpuint(decoded->len, ==, 2);
}

static guint32
be(const char *dotted)
{
    struct in_addr addr;

    inet_pton(AF_INET, dotted, &addr);
    return addr.s_addr;
}

static void
assert_range_cidrs(const char *from, const char *to, const char *const *expected, guint expected_len)
{
    g_autoptr(GPtrArray) cidrs = snx_ip4_range_to_cidrs(be(from), be(to));
    guint i;

    g_assert_cmpuint(cidrs->len, ==, expected_len);
    for (i = 0; i < expected_len; i++)
        g_assert_cmpstr(g_ptr_array_index(cidrs, i), ==, expected[i]);
}

static void
test_range_to_cidrs(void)
{
    static const char *const class_a[] = {"10.0.0.0/8"};
    static const char *const class_c[] = {"192.168.1.0/24"};
    static const char *const misaligned[] = {
        "192.168.1.5/32",
        "192.168.1.6/31",
        "192.168.1.8/31",
        "192.168.1.10/32",
    };
    static const char *const two_class_b[] = {"172.30.0.0/15"};

    assert_range_cidrs("10.0.0.0", "10.255.255.255", class_a, G_N_ELEMENTS(class_a));
    assert_range_cidrs("192.168.1.0", "192.168.1.255", class_c, G_N_ELEMENTS(class_c));
    assert_range_cidrs("192.168.1.5", "192.168.1.10", misaligned, G_N_ELEMENTS(misaligned));
    assert_range_cidrs("172.30.0.0", "172.31.255.255", two_class_b, G_N_ELEMENTS(two_class_b));
}

static void
test_private_subnet_route_for_host(void)
{
    g_autofree char *route_10 = snx_ip4_private_subnet_route_for_host("10.200.0.198");
    g_autofree char *route_172 = snx_ip4_private_subnet_route_for_host("172.20.0.198");
    g_autofree char *route_192 = snx_ip4_private_subnet_route_for_host("192.168.3.1");
    g_autofree char *route_public = snx_ip4_private_subnet_route_for_host("8.8.8.8");
    g_autofree char *route_invalid = snx_ip4_private_subnet_route_for_host("not-an-ip");

    g_assert_cmpstr(route_10, ==, "10.200.0.0/16");
    g_assert_cmpstr(route_172, ==, "172.20.0.0/16");
    g_assert_cmpstr(route_192, ==, "192.168.3.0/24");
    g_assert_null(route_public);
    g_assert_null(route_invalid);
}

static void
test_invalid_route(void)
{
    g_autoptr(GPtrArray) route_specs = g_ptr_array_new_with_free_func(g_free);
    g_autoptr(GPtrArray) routes = NULL;
    g_autoptr(GError) error = NULL;

    g_ptr_array_add(route_specs, g_strdup("192.0.2.1/33"));
    routes = snx_ip4_routes_from_strings(route_specs, &error);
    g_assert_null(routes);
    g_assert_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/ip4/domain-normalization", test_domain_normalization);
    g_test_add_func("/ip4/ipv4-conversion", test_ipv4_conversion);
    g_test_add_func("/ip4/config-variant", test_ip4_config_variant);
    g_test_add_func("/ip4/config-non-routing-domain", test_ip4_config_non_routing_domain);
    g_test_add_func("/ip4/route-conversion", test_route_conversion);
    g_test_add_func("/ip4/range-to-cidrs", test_range_to_cidrs);
    g_test_add_func("/ip4/private-subnet-route-for-host", test_private_subnet_route_for_host);
    g_test_add_func("/ip4/invalid-route", test_invalid_route);
    return g_test_run();
}
