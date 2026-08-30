/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

/* Key names match networkmanager-snx's own NMVpnServicePlugin; see
 * ../src/snx-config.c (snx_config_apply_item()) for the authoritative list. */

#ifndef NM_SNX_SERVICE_H
#define NM_SNX_SERVICE_H

#define NM_DBUS_SERVICE_SNX "org.freedesktop.NetworkManager.snx"

#define NM_SNX_KEY_SERVER_NAME "server-name"
#define NM_SNX_KEY_LOGIN_TYPE "login-type"
#define NM_SNX_KEY_TUNNEL_TYPE "tunnel-type"
#define NM_SNX_KEY_TRANSPORT_TYPE "transport-type"
#define NM_SNX_KEY_IF_NAME "if-name"
#define NM_SNX_KEY_MTU "mtu"

#define NM_SNX_KEY_CERT_TYPE "cert-type"
#define NM_SNX_KEY_CERT_PATH "cert-path"
#define NM_SNX_KEY_CERT_ID "cert-id"
#define NM_SNX_KEY_CA_CERT "ca-cert"
#define NM_SNX_KEY_IGNORE_SERVER_CERT "ignore-server-cert"

#define NM_SNX_KEY_DEFAULT_ROUTE "default-route"
#define NM_SNX_KEY_NO_ROUTING "no-routing"
#define NM_SNX_KEY_ADD_ROUTES "add-routes"
#define NM_SNX_KEY_IGNORE_ROUTES "ignore-routes"
#define NM_SNX_KEY_ALLOW_FORWARDING "allow-forwarding"

#define NM_SNX_KEY_DNS_SERVERS "dns-servers"
#define NM_SNX_KEY_IGNORE_DNS_SERVERS "ignore-dns-servers"
#define NM_SNX_KEY_SEARCH_DOMAINS "search-domains"
#define NM_SNX_KEY_IGNORE_SEARCH_DOMAINS "ignore-search-domains"
#define NM_SNX_KEY_SET_ROUTING_DOMAINS "set-routing-domains"
#define NM_SNX_KEY_DNS_PRIORITY "dns-priority"
#define NM_SNX_KEY_DISABLE_IPV6 "disable-ipv6"

#define NM_SNX_KEY_NO_KEEPALIVE "no-keepalive"
#define NM_SNX_KEY_PORT_KNOCK "port-knock"
#define NM_SNX_KEY_IKE_PERSIST "ike-persist"
#define NM_SNX_KEY_IKE_LIFETIME "ike-lifetime"
#define NM_SNX_KEY_IP_LEASE_TIME "ip-lease-time"

#define NM_SNX_KEY_PASSWORD "password"
#define NM_SNX_KEY_CERT_PASSWORD "cert-password"

#endif /* NM_SNX_SERVICE_H */
