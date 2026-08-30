/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#define _GNU_SOURCE

#include "snx-netlink.h"

#include "snx-errors.h"

#include <errno.h>
#include <linux/if.h>
#include <linux/if_addr.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/sockios.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define SNX_NL_BUF_SIZE 512

static int
if_index_for_name(const char *ifname, GError **error)
{
    int sock;
    struct ifreq ifr;
    int index;

    sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (sock < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "socket() failed: %s", g_strerror(errno));
        return -1;
    }

    memset(&ifr, 0, sizeof(ifr));
    g_strlcpy(ifr.ifr_name, ifname, IFNAMSIZ);

    if (ioctl(sock, SIOCGIFINDEX, &ifr) < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "SIOCGIFINDEX failed for \"%s\": %s", ifname,
                   g_strerror(errno));
        close(sock);
        return -1;
    }

    index = ifr.ifr_ifindex;
    close(sock);
    return index;
}

static gboolean
nl_put_attr(struct nlmsghdr *nlh, gsize buf_size, unsigned short type, const void *data, gsize len, GError **error)
{
    gsize attr_offset = NLMSG_ALIGN(nlh->nlmsg_len);
    gsize attr_len = RTA_LENGTH(len);
    struct rtattr *rta;

    if (attr_offset + RTA_ALIGN(attr_len) > buf_size) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink request buffer overflow");
        return FALSE;
    }

    rta = (struct rtattr *) ((guint8 *) nlh + attr_offset);
    rta->rta_type = type;
    rta->rta_len = (unsigned short) attr_len;
    if (len > 0)
        memcpy(RTA_DATA(rta), data, len);

    nlh->nlmsg_len = (guint32) (attr_offset + attr_len);
    return TRUE;
}

static gboolean
nl_send_and_check(struct nlmsghdr *nlh, GError **error)
{
    int sock;
    struct sockaddr_nl addr;
    guint8 rbuf[4096];
    ssize_t n;
    gboolean ok = FALSE;

    nlh->nlmsg_flags |= NLM_F_ACK;
    nlh->nlmsg_pid = 0;

    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink socket() failed: %s", g_strerror(errno));
        return FALSE;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink bind() failed: %s", g_strerror(errno));
        close(sock);
        return FALSE;
    }

    if (send(sock, nlh, NLMSG_ALIGN(nlh->nlmsg_len), 0) < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink send() failed: %s", g_strerror(errno));
        close(sock);
        return FALSE;
    }

    n = recv(sock, rbuf, sizeof(rbuf), 0);
    if (n < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink recv() failed: %s", g_strerror(errno));
        close(sock);
        return FALSE;
    }

    {
        struct nlmsghdr *rnlh = (struct nlmsghdr *) rbuf;

        if ((gsize) n >= sizeof(struct nlmsghdr) && NLMSG_OK(rnlh, (gsize) n) && rnlh->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(rnlh);

            if (nlerr->error == 0)
                ok = TRUE;
            else
                g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink operation failed: %s",
                           g_strerror(-nlerr->error));
        } else {
            g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "unexpected netlink reply");
        }
    }

    close(sock);
    return ok;
}

gboolean
snx_netlink_link_up(const char *ifname, guint mtu, GError **error)
{
    guint8 buf[SNX_NL_BUF_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
    struct ifinfomsg *ifi;
    guint32 mtu_value = mtu;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlh->nlmsg_type = RTM_NEWLINK;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;

    ifi = (struct ifinfomsg *) NLMSG_DATA(nlh);
    ifi->ifi_family = AF_UNSPEC;
    ifi->ifi_flags = IFF_UP;
    ifi->ifi_change = IFF_UP;

    if (!nl_put_attr(nlh, sizeof(buf), IFLA_IFNAME, ifname, strlen(ifname) + 1, error))
        return FALSE;
    if (!nl_put_attr(nlh, sizeof(buf), IFLA_MTU, &mtu_value, sizeof(mtu_value), error))
        return FALSE;

    return nl_send_and_check(nlh, error);
}

gboolean
snx_netlink_addr_add(const char *ifname, guint32 address_be, guint8 prefix_len, GError **error)
{
    guint8 buf[SNX_NL_BUF_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
    struct ifaddrmsg *ifa;
    int index = if_index_for_name(ifname, error);

    if (index < 0)
        return FALSE;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_type = RTM_NEWADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_seq = 1;

    ifa = (struct ifaddrmsg *) NLMSG_DATA(nlh);
    ifa->ifa_family = AF_INET;
    ifa->ifa_prefixlen = prefix_len;
    ifa->ifa_scope = RT_SCOPE_UNIVERSE;
    ifa->ifa_index = (guint32) index;

    if (!nl_put_attr(nlh, sizeof(buf), IFA_LOCAL, &address_be, sizeof(address_be), error))
        return FALSE;
    if (!nl_put_attr(nlh, sizeof(buf), IFA_ADDRESS, &address_be, sizeof(address_be), error))
        return FALSE;

    return nl_send_and_check(nlh, error);
}

static gboolean
ifname_for_index(guint32 index, char *out_ifname, gsize ifname_size)
{
    int sock = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    struct ifreq ifr;
    gboolean ok = FALSE;

    if (sock < 0)
        return FALSE;

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_ifindex = (int) index;
    if (ioctl(sock, SIOCGIFNAME, &ifr) == 0) {
        g_strlcpy(out_ifname, ifr.ifr_name, ifname_size);
        ok = TRUE;
    }

    close(sock);
    return ok;
}

gboolean
snx_netlink_get_route_gateway(guint32 destination_be,
                              guint32 *out_gateway_be,
                              char *out_ifname,
                              gsize ifname_size,
                              GError **error)
{
    guint8 buf[SNX_NL_BUF_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
    struct rtmsg *rtm;
    int sock;
    struct sockaddr_nl addr;
    guint8 rbuf[4096];
    ssize_t n;
    struct nlmsghdr *rnlh;
    struct rtattr *rta;
    int rta_len;
    guint32 oif = 0;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;

    rtm = (struct rtmsg *) NLMSG_DATA(nlh);
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = 32;

    if (!nl_put_attr(nlh, sizeof(buf), RTA_DST, &destination_be, sizeof(destination_be), error))
        return FALSE;

    sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink socket() failed: %s", g_strerror(errno));
        return FALSE;
    }

    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    if (bind(sock, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink bind() failed: %s", g_strerror(errno));
        close(sock);
        return FALSE;
    }

    if (send(sock, nlh, NLMSG_ALIGN(nlh->nlmsg_len), 0) < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink send() failed: %s", g_strerror(errno));
        close(sock);
        return FALSE;
    }

    n = recv(sock, rbuf, sizeof(rbuf), 0);
    close(sock);
    if (n < 0) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "netlink recv() failed: %s", g_strerror(errno));
        return FALSE;
    }

    rnlh = (struct nlmsghdr *) rbuf;
    if ((gsize) n < sizeof(struct nlmsghdr) || !NLMSG_OK(rnlh, (gsize) n)) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "malformed netlink route lookup reply");
        return FALSE;
    }

    if (rnlh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *nlerr = (struct nlmsgerr *) NLMSG_DATA(rnlh);

        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "route lookup failed: %s",
                   g_strerror(-nlerr->error));
        return FALSE;
    }

    if (rnlh->nlmsg_type != RTM_NEWROUTE) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "unexpected netlink route lookup reply type %u",
                   rnlh->nlmsg_type);
        return FALSE;
    }

    *out_gateway_be = 0;
    rta = (struct rtattr *) ((guint8 *) rnlh + NLMSG_LENGTH(sizeof(struct rtmsg)));
    rta_len = (int) (rnlh->nlmsg_len - NLMSG_LENGTH(sizeof(struct rtmsg)));
    for (; RTA_OK(rta, rta_len); rta = RTA_NEXT(rta, rta_len)) {
        if (rta->rta_type == RTA_GATEWAY)
            memcpy(out_gateway_be, RTA_DATA(rta), sizeof(*out_gateway_be));
        else if (rta->rta_type == RTA_OIF)
            memcpy(&oif, RTA_DATA(rta), sizeof(oif));
    }

    if (oif == 0 || !ifname_for_index(oif, out_ifname, ifname_size)) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_ADDRESS, "route lookup did not return a usable interface");
        return FALSE;
    }

    return TRUE;
}

gboolean
snx_netlink_route_add(const char *ifname,
                      guint32 destination_be,
                      guint8 prefix_len,
                      guint32 gateway_be,
                      GError **error)
{
    guint8 buf[SNX_NL_BUF_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
    struct rtmsg *rtm;
    int index = if_index_for_name(ifname, error);
    guint32 oif;

    if (index < 0)
        return FALSE;
    oif = (guint32) index;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_NEWROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
    nlh->nlmsg_seq = 1;

    rtm = (struct rtmsg *) NLMSG_DATA(nlh);
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = prefix_len;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope = gateway_be != 0 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    rtm->rtm_type = RTN_UNICAST;

    if (!nl_put_attr(nlh, sizeof(buf), RTA_DST, &destination_be, sizeof(destination_be), error))
        return FALSE;
    if (!nl_put_attr(nlh, sizeof(buf), RTA_OIF, &oif, sizeof(oif), error))
        return FALSE;
    if (gateway_be != 0 && !nl_put_attr(nlh, sizeof(buf), RTA_GATEWAY, &gateway_be, sizeof(gateway_be), error))
        return FALSE;

    return nl_send_and_check(nlh, error);
}

gboolean
snx_netlink_route_del(const char *ifname,
                      guint32 destination_be,
                      guint8 prefix_len,
                      guint32 gateway_be,
                      GError **error)
{
    guint8 buf[SNX_NL_BUF_SIZE];
    struct nlmsghdr *nlh = (struct nlmsghdr *) buf;
    struct rtmsg *rtm;
    int index = if_index_for_name(ifname, error);
    guint32 oif;

    if (index < 0)
        return FALSE;
    oif = (guint32) index;

    memset(buf, 0, sizeof(buf));
    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_DELROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST;
    nlh->nlmsg_seq = 1;

    rtm = (struct rtmsg *) NLMSG_DATA(nlh);
    rtm->rtm_family = AF_INET;
    rtm->rtm_dst_len = prefix_len;
    rtm->rtm_table = RT_TABLE_MAIN;
    rtm->rtm_protocol = RTPROT_STATIC;
    rtm->rtm_scope = gateway_be != 0 ? RT_SCOPE_UNIVERSE : RT_SCOPE_LINK;
    rtm->rtm_type = RTN_UNICAST;

    if (!nl_put_attr(nlh, sizeof(buf), RTA_DST, &destination_be, sizeof(destination_be), error))
        return FALSE;
    if (!nl_put_attr(nlh, sizeof(buf), RTA_OIF, &oif, sizeof(oif), error))
        return FALSE;
    if (gateway_be != 0 && !nl_put_attr(nlh, sizeof(buf), RTA_GATEWAY, &gateway_be, sizeof(gateway_be), error))
        return FALSE;

    return nl_send_and_check(nlh, error);
}
