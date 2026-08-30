/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#define _GNU_SOURCE

#include "snx-tun.h"

#include "snx-errors.h"

/* linux/if.h (not net/if.h) so that IFF_TUN/IFF_NO_PI from linux/if_tun.h
 * and struct ifreq come from the same kernel UAPI headers; mixing glibc's
 * net/if.h with linux/if_tun.h fails to compile on this system. */
#include <errno.h>
#include <fcntl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>

int
snx_tun_create(const char *name_hint, char **out_name, GError **error)
{
    struct ifreq ifr;
    int fd;

    fd = open("/dev/net/tun", O_RDWR | O_CLOEXEC);
    if (fd < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "failed to open /dev/net/tun: %s",
                   g_strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    if (name_hint != NULL)
        g_strlcpy(ifr.ifr_name, name_hint, IFNAMSIZ);

    if (ioctl(fd, TUNSETIFF, &ifr) < 0) {
        int saved_errno = errno;

        close(fd);
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "TUNSETIFF failed for \"%s\": %s",
                   name_hint != NULL ? name_hint : "(auto)", g_strerror(saved_errno));
        return -1;
    }

    *out_name = g_strndup(ifr.ifr_name, IFNAMSIZ);
    return fd;
}
