/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-ip4-config.h"

#include "snx-errors.h"

#include <arpa/inet.h>
#include <errno.h>
#include <string.h>

gboolean
snx_ipv4_to_nm_u32(const char *address, guint32 *out, GError **error)
{
    struct in_addr parsed;

    if (address == NULL || inet_pton(AF_INET, address, &parsed) != 1) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "invalid IPv4 address: %s",
                    address != NULL ? address : "(null)");
        return FALSE;
    }

    memcpy(out, &parsed.s_addr, sizeof(*out));
    return TRUE;
}

static gboolean
parse_prefix(const char *value, guint *out, GError **error)
{
    char *end = NULL;
    unsigned long parsed;

    errno = 0;
    parsed = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0' || parsed > 32) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "invalid IPv4 route prefix: %s", value);
        return FALSE;
    }

    *out = (guint) parsed;
    return TRUE;
}

static char *
normalize_route_destination(const char *address, guint prefix, GError **error)
{
    struct in_addr parsed;
    guint32 host_order;
    guint32 mask;
    struct in_addr normalized;
    char buffer[INET_ADDRSTRLEN];

    if (inet_pton(AF_INET, address, &parsed) != 1) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "invalid IPv4 route destination: %s", address);
        return NULL;
    }

    host_order = ntohl(parsed.s_addr);
    mask = prefix == 0 ? 0 : (G_MAXUINT32 << (32 - prefix));
    normalized.s_addr = htonl(host_order & mask);

    if (inet_ntop(AF_INET, &normalized, buffer, sizeof(buffer)) == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "failed to format IPv4 route destination");
        return NULL;
    }

    return g_strdup(buffer);
}

static NMIPRoute *
parse_route_spec(const char *spec, GError **error)
{
    g_auto(GStrv) parts = NULL;
    g_autofree char *copy = NULL;
    g_autofree char *dest = NULL;
    g_autofree char *normalized_dest = NULL;
    char *slash;
    guint prefix;

    if (spec == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "missing IPv4 route");
        return NULL;
    }

    copy = g_strdup(spec);
    g_strstrip(copy);
    if (*copy == '\0') {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "empty IPv4 route");
        return NULL;
    }

    parts = g_strsplit_set(copy, " \t", -1);
    if (parts[0] == NULL || parts[0][0] == '\0' || parts[1] != NULL) {
        g_set_error(error,
                    SNX_ERROR,
                    SNX_ERROR_INVALID_CONFIG,
                    "invalid IPv4 route format, expected destination/prefix: %s",
                    spec);
        return NULL;
    }

    slash = strchr(parts[0], '/');
    if (slash == NULL || slash == parts[0] || slash[1] == '\0' || strchr(slash + 1, '/') != NULL) {
        g_set_error(error,
                    SNX_ERROR,
                    SNX_ERROR_INVALID_CONFIG,
                    "invalid IPv4 route format, expected destination/prefix: %s",
                    spec);
        return NULL;
    }

    *slash = '\0';
    dest = g_strdup(parts[0]);
    if (!parse_prefix(slash + 1, &prefix, error))
        return NULL;

    normalized_dest = normalize_route_destination(dest, prefix, error);
    if (normalized_dest == NULL)
        return NULL;

    return nm_ip_route_new(AF_INET, normalized_dest, prefix, NULL, -1, error);
}

GPtrArray *
snx_ip4_routes_from_strings(const GPtrArray *route_specs, GError **error)
{
    GPtrArray *routes = g_ptr_array_new_with_free_func((GDestroyNotify) nm_ip_route_unref);

    if (route_specs == NULL)
        return routes;

    for (guint i = 0; i < route_specs->len; i++) {
        NMIPRoute *route = parse_route_spec(g_ptr_array_index(route_specs, i), error);
        if (route == NULL) {
            g_ptr_array_unref(routes);
            return NULL;
        }
        g_ptr_array_add(routes, route);
    }

    return routes;
}

GPtrArray *
snx_ip4_range_to_cidrs(guint32 from_be, guint32 to_be)
{
    GPtrArray *specs = g_ptr_array_new_with_free_func(g_free);
    guint32 from = ntohl(from_be);
    guint32 to = ntohl(to_be);

    if (from > to)
        return specs;

    for (;;) {
        guint8 prefix = 32;
        guint32 size = 1;

        for (;;) {
            guint32 next_size = size * 2;

            if (next_size == 0)
                break; /* would overflow past the widest representable block */
            if ((from & (next_size - 1)) != 0)
                break; /* from is not aligned to a block this wide */
            if ((guint64) from + next_size - 1 > to)
                break; /* block would extend past the end of the range */

            prefix--;
            size = next_size;
        }

        {
            struct in_addr addr;
            char buf[INET_ADDRSTRLEN];

            addr.s_addr = htonl(from);
            inet_ntop(AF_INET, &addr, buf, sizeof(buf));
            g_ptr_array_add(specs, g_strdup_printf("%s/%u", buf, prefix));
        }

        if ((guint64) from + size > to)
            break;
        from += size;
    }

    return specs;
}

char *
snx_ip4_private_subnet_route_for_host(const char *address)
{
    struct in_addr addr;
    guint32 host_order;
    guint32 network;
    guint prefix;
    char buf[INET_ADDRSTRLEN];

    if (address == NULL || inet_pton(AF_INET, address, &addr) != 1)
        return NULL;

    host_order = ntohl(addr.s_addr);

    if ((host_order & 0xff000000u) == 0x0a000000u) {
        network = host_order & 0xffff0000u;
        prefix = 16;
    } else if ((host_order & 0xfff00000u) == 0xac100000u) {
        network = host_order & 0xffff0000u;
        prefix = 16;
    } else if ((host_order & 0xffff0000u) == 0xc0a80000u) {
        network = host_order & 0xffffff00u;
        prefix = 24;
    } else {
        return NULL;
    }

    addr.s_addr = htonl(network);
    if (inet_ntop(AF_INET, &addr, buf, sizeof(buf)) == NULL)
        return NULL;

    return g_strdup_printf("%s/%u", buf, prefix);
}

char *
snx_normalize_routing_domain(const char *domain)
{
    char *copy;
    char *trimmed;
    gsize len;

    if (domain == NULL)
        return NULL;

    copy = g_strdup(domain);
    trimmed = g_strstrip(copy);
    if (*trimmed == '\0' || g_str_equal(trimmed, ".") || g_str_equal(trimmed, "~") || g_str_equal(trimmed, "~.")) {
        g_free(copy);
        return NULL;
    }

    len = strlen(trimmed);
    while (len > 0 && trimmed[len - 1] == '.')
        trimmed[--len] = '\0';

    if (g_str_has_prefix(trimmed, "~")) {
        char *result = g_strdup(trimmed);
        g_free(copy);
        return result;
    }

    char *result = g_strconcat("~", trimmed, NULL);
    g_free(copy);
    return result;
}

static char *
snx_normalize_search_domain(const char *domain, gboolean route_domain)
{
    char *copy;
    char *trimmed;
    gsize len;

    if (route_domain)
        return snx_normalize_routing_domain(domain);

    if (domain == NULL)
        return NULL;

    copy = g_strdup(domain);
    trimmed = g_strstrip(copy);
    if (*trimmed == '\0' || g_str_equal(trimmed, ".") || g_str_equal(trimmed, "~") || g_str_equal(trimmed, "~.")) {
        g_free(copy);
        return NULL;
    }

    len = strlen(trimmed);
    while (len > 0 && trimmed[len - 1] == '.')
        trimmed[--len] = '\0';

    {
        char *result = g_strdup(trimmed);
        g_free(copy);
        return result;
    }
}

GVariant *
snx_ip4_config_new(const char *address,
                   guint prefix,
                   const GPtrArray *routes,
                   const GPtrArray *dns_servers,
                   const GPtrArray *domains,
                   gboolean never_default,
                   gint dns_priority,
                   gboolean route_domains,
                   GError **error)
{
    GVariantBuilder builder;
    GVariantBuilder dns_builder;
    GPtrArray *normalized_domains;
    guint32 addr;

    if (prefix == 0 || prefix > 32) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "invalid IPv4 prefix: %u", prefix);
        return NULL;
    }

    if (!snx_ipv4_to_nm_u32(address, &addr, error))
        return NULL;

    g_variant_builder_init(&builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&builder, "{sv}", "address", g_variant_new_uint32(addr));
    g_variant_builder_add(&builder, "{sv}", "prefix", g_variant_new_uint32(prefix));
    g_variant_builder_add(&builder, "{sv}", "never-default", g_variant_new_boolean(never_default));
    g_variant_builder_add(&builder, "{sv}", "dns-priority", g_variant_new_int32(dns_priority));

    if (routes != NULL && routes->len > 0)
        g_variant_builder_add(&builder, "{sv}", "routes", nm_utils_ip4_routes_to_variant((GPtrArray *) routes));

    g_variant_builder_init(&dns_builder, G_VARIANT_TYPE("au"));
    if (dns_servers != NULL) {
        for (guint i = 0; i < dns_servers->len; i++) {
            guint32 dns_addr;
            const char *dns = g_ptr_array_index(dns_servers, i);
            if (!snx_ipv4_to_nm_u32(dns, &dns_addr, error))
                return NULL;
            g_variant_builder_add(&dns_builder, "u", dns_addr);
        }
    }
    g_variant_builder_add(&builder, "{sv}", "dns", g_variant_builder_end(&dns_builder));

    normalized_domains = g_ptr_array_new_with_free_func(g_free);
    if (domains != NULL) {
        for (guint i = 0; i < domains->len; i++) {
            char *normalized = snx_normalize_search_domain(g_ptr_array_index(domains, i), route_domains);
            if (normalized != NULL)
                g_ptr_array_add(normalized_domains, normalized);
        }
    }

    if (normalized_domains->len > 0) {
        const char **strv = g_new0(const char *, normalized_domains->len + 1);
        for (guint i = 0; i < normalized_domains->len; i++)
            strv[i] = g_ptr_array_index(normalized_domains, i);
        g_variant_builder_add(&builder, "{sv}", "domains", g_variant_new_strv(strv, -1));
        g_free(strv);
    }

    g_ptr_array_unref(normalized_domains);
    return g_variant_ref_sink(g_variant_builder_end(&builder));
}
