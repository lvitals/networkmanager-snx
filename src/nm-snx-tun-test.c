/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-netlink.h"
#include "snx-tun.h"

#include <arpa/inet.h>
#include <glib-unix.h>
#include <glib.h>
#include <stdio.h>
#include <unistd.h>

/*
 * Standalone diagnostic for the low-level TUN + netlink primitives, kept
 * separate from the full VPN connect flow so a problem here is easy to
 * isolate. Not part of the NetworkManager plugin chain; run manually
 * (as root, since interface creation needs CAP_NET_ADMIN) to sanity-check
 * this environment before relying on the same code inside nm-snx-service.
 *
 * Usage: sudo ./nm-snx-tun-test [ifname-hint]
 *
 * Creates a TUN device, brings it up, assigns a private test address and a
 * route, then waits for Ctrl-C so you can inspect it with `ip addr show`
 * and `ip route show` from another terminal. Closing (or Ctrl-C) removes
 * the interface automatically.
 */

static gboolean
on_sigint(gpointer user_data)
{
    g_main_loop_quit((GMainLoop *) user_data);
    return G_SOURCE_REMOVE;
}

int
main(int argc, char **argv)
{
    const char *name_hint = argc > 1 ? argv[1] : "snxtun-test";
    g_autofree char *tun_name = NULL;
    g_autoptr(GError) error = NULL;
    g_autoptr(GMainLoop) loop = NULL;
    int fd;
    guint32 address_be;
    guint32 route_be;

    g_print("1) Opening /dev/net/tun and creating \"%s\"...\n", name_hint);
    fd = snx_tun_create(name_hint, &tun_name, &error);
    if (fd < 0) {
        g_printerr("   FAILED: %s\n", error->message);
        g_printerr("   (Needs root/CAP_NET_ADMIN; run with sudo.)\n");
        return 1;
    }
    g_print("   OK: kernel assigned interface name \"%s\", fd=%d\n", tun_name, fd);

    g_print("2) Bringing \"%s\" up with MTU 1300...\n", tun_name);
    if (!snx_netlink_link_up(tun_name, 1300, &error)) {
        g_printerr("   FAILED: %s\n", error->message);
        close(fd);
        return 1;
    }
    g_print("   OK\n");

    inet_pton(AF_INET, "10.201.55.1", &address_be);
    g_print("3) Assigning address 10.201.55.1/24...\n");
    if (!snx_netlink_addr_add(tun_name, address_be, 24, &error)) {
        g_printerr("   FAILED: %s\n", error->message);
        close(fd);
        return 1;
    }
    g_print("   OK\n");

    inet_pton(AF_INET, "10.202.0.0", &route_be);
    g_print("4) Adding route 10.202.0.0/16 via %s (on-link)...\n", tun_name);
    if (!snx_netlink_route_add(tun_name, route_be, 16, 0, &error)) {
        g_printerr("   FAILED: %s\n", error->message);
        close(fd);
        return 1;
    }
    g_print("   OK\n");

    g_print("\nAll steps succeeded. Inspect with, e.g.:\n");
    g_print("  ip addr show %s\n", tun_name);
    g_print("  ip route show dev %s\n", tun_name);
    g_print("Press Ctrl-C to remove the interface and exit.\n");

    loop = g_main_loop_new(NULL, FALSE);
    g_unix_signal_add(SIGINT, on_sigint, loop);
    g_unix_signal_add(SIGTERM, on_sigint, loop);
    g_main_loop_run(loop);

    close(fd);
    g_print("Closed %s.\n", tun_name);

    return 0;
}
