/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_IP4_CONFIG_H
#define SNX_IP4_CONFIG_H

#include <NetworkManager.h>
#include <glib.h>

gboolean snx_ipv4_to_nm_u32(const char *address, guint32 *out, GError **error);
GPtrArray *snx_ip4_routes_from_strings(const GPtrArray *route_specs, GError **error);

/* Decomposes an inclusive [from_be, to_be] IPv4 address range (network byte
 * order, as used by gateway-provided "range" entries) into the minimal set
 * of CIDR blocks that exactly cover it, returned as newly-allocated
 * "a.b.c.d/N" strings (suitable for snx_ip4_routes_from_strings()). */
GPtrArray *snx_ip4_range_to_cidrs(guint32 from_be, guint32 to_be);
char *snx_ip4_private_subnet_route_for_host(const char *address);
char *snx_normalize_routing_domain(const char *domain);
GVariant *snx_ip4_config_new(const char *address,
                             guint prefix,
                             const GPtrArray *routes,
                             const GPtrArray *dns_servers,
                             const GPtrArray *domains,
                             gboolean never_default,
                             gint dns_priority,
                             gboolean route_domains,
                             GError **error);

#endif
