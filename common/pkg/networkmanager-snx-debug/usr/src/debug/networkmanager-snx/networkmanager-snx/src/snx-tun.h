/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#ifndef SNX_TUN_H
#define SNX_TUN_H

#include <glib.h>

/*
 * Creates a Linux TUN network interface via /dev/net/tun (TUNSETIFF), with
 * no ip/ifconfig/other external command. name_hint is used as the kernel
 * interface name request; on success *out_name receives the name the
 * kernel actually assigned (normally the same, unless name_hint contained
 * a kernel "%d" placeholder). Requires CAP_NET_ADMIN.
 *
 * Returns the open, non-blocking file descriptor for reading/writing raw
 * IP packets on the interface (owned by the caller; close() it to remove
 * the interface), or -1 on error.
 */
int snx_tun_create(const char *name_hint, char **out_name, GError **error);

#endif
