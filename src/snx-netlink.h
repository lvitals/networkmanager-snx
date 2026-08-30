/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_NETLINK_H
#define SNX_NETLINK_H

#include <glib.h>

/*
 * Configures the tunnel interface directly through NETLINK_ROUTE (no
 * ip/ifconfig/route commands), matching the project's principle of never
 * shelling out to configure networking.
 *
 * Addresses are passed as guint32 in network byte order (the same layout
 * as struct in_addr.s_addr / inet_addr()).
 */

/* Brings the named interface up and sets its MTU. */
gboolean snx_netlink_link_up(const char *ifname, guint mtu, GError **error);

/* Assigns an IPv4 address with the given prefix length to the interface. */
gboolean snx_netlink_addr_add(const char *ifname, guint32 address_be, guint8 prefix_len, GError **error);

/* Adds an IPv4 route via the interface. gateway_be may be 0 for a
 * directly-connected/on-link route (the normal case for a point-to-point
 * tunnel interface). */
gboolean snx_netlink_route_add(const char *ifname,
                               guint32 destination_be,
                               guint8 prefix_len,
                               guint32 gateway_be,
                               GError **error);

/* Removes an IPv4 route previously added with snx_netlink_route_add(),
 * identified by the same (ifname, destination_be, prefix_len, gateway_be)
 * tuple. */
gboolean snx_netlink_route_del(const char *ifname,
                               guint32 destination_be,
                               guint8 prefix_len,
                               guint32 gateway_be,
                               GError **error);

/* Read-only: asks the kernel which gateway/interface is currently used to
 * reach destination_be (matching what "ip route get" reports), before any
 * of this plugin's own routes are added. Used to add an explicit host
 * route to the VPN gateway itself before replacing the default route, so
 * the tunnel's own TCP connection doesn't get routed through the tunnel it
 * depends on. *out_gateway_be is set to 0 when the destination is
 * on-link (no gateway hop). */
gboolean snx_netlink_get_route_gateway(guint32 destination_be,
                                       guint32 *out_gateway_be,
                                       char *out_ifname,
                                       gsize ifname_size,
                                       GError **error);

#endif
