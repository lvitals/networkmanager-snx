/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-ccc.h"
#include "snx-config.h"
#include "snx-errors.h"
#include "snx-ip4-config.h"
#include "snx-netlink.h"
#include "snx-service-name.h"
#include "snx-sexpr.h"
#include "snx-slim.h"
#include "snx-ssl-tunnel.h"
#include "snx-tun.h"

#include <NetworkManager.h>
#include <arpa/inet.h>
#include <errno.h>
#include <glib-unix.h>
#include <net/if.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/eventfd.h>
#include <unistd.h>

static void snx_vpn_plugin_initable_iface_init(GInitableIface *iface);

typedef struct {
    NMVpnServicePlugin parent;

    /* Parsed at the start of Connect()/ConnectInteractive(), read by every
     * later async step; cleared and re-parsed on every connection attempt. */
    SnxConfig config;
    char *username;
    char *password;

    /* CCC authentication state, carried across an MFA "continue" ->
     * NewSecrets() round trip. */
    char *ccc_session_id;
    gboolean awaiting_challenge;
    guint16 tcpt_port;
    char *gateway_ip; /* resolved server_ip from CCC discovery, dotted-quad string */

    /* Cancels the in-flight async auth/tunnel step (if any) so a
     * Disconnect() or a new Connect() that arrives while one is still
     * running can't race its completion and publish state after teardown
     * has already run. Recreated at the start of every Connect(). */
    GCancellable *cancellable;

    /* Tunnel runtime, valid once connected. tun_fd is -1 when not open. */
    SnxSslTunnel *tunnel;
    int tun_fd;
    char *tun_name;
    GThread *uplink_thread;
    GThread *downlink_thread;

    /* eventfd the uplink thread also polls alongside tun_fd. Unlike the
     * downlink thread (blocked on the tunnel's network socket, which
     * shutdown() reliably interrupts from another thread), the uplink
     * thread blocks reading tun_fd -- a plain close(tun_fd) from
     * teardown_tunnel() is not guaranteed to promptly wake a concurrent
     * blocking read() on the same fd from another thread, and in practice
     * can leave it blocked for tens of seconds with no local traffic to
     * read, stalling teardown_tunnel()'s g_thread_join() on it (and with
     * it Disconnect() and the whole process) for that long. Writing to
     * this eventfd is what actually wakes the poll() promptly. -1 when
     * not open. */
    int uplink_wake_fd;
    gint keepalive_misses;
    guint keepalive_source_id;

    /* The gateway bypass host route added by configure_interface() when
     * default_route is set (see there): unlike every other route this
     * plugin adds, it lives on the original physical interface, not
     * tun_name, so neither NetworkManager's own Ip4Config revert nor the
     * kernel destroying the tun device on disconnect removes it. Tracked
     * here so teardown_tunnel() can remove it explicitly. */
    gboolean bypass_route_active;
    char bypass_route_ifname[IF_NAMESIZE];
    guint32 bypass_route_dest_be;
    guint32 bypass_route_gateway_be;

    /* Set by teardown_tunnel() before it closes the tunnel/fd, so the
     * forwarding threads that unblocks can tell an intentional teardown
     * apart from a real link failure and skip self-reporting in the
     * former case. unexpected_exit_reported guards against both threads
     * (uplink and downlink share one tunnel, so a link failure tends to
     * break both at once) each posting their own Failure signal. */
    gint tearing_down;
    gint unexpected_exit_reported;
} SnxVpnPlugin;

typedef struct {
    NMVpnServicePluginClass parent_class;
} SnxVpnPluginClass;

G_DEFINE_TYPE_WITH_CODE(SnxVpnPlugin,
                        snx_vpn_plugin,
                        NM_TYPE_VPN_SERVICE_PLUGIN,
                        G_IMPLEMENT_INTERFACE(G_TYPE_INITABLE, snx_vpn_plugin_initable_iface_init))

#define SNX_VPN_PLUGIN(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), snx_vpn_plugin_get_type(), SnxVpnPlugin))

static GInitableIface *initable_parent_iface;

#define SNX_KEEPALIVE_MAX_MISSES 3

/* ---- small helpers ---- */

G_GNUC_PRINTF(3, 4)
static void
report_failure(SnxVpnPlugin *self, NMVpnPluginFailure reason, const char *format, ...)
{
    va_list args;
    g_autofree char *message = NULL;

    va_start(args, format);
    message = g_strdup_vprintf(format, args);
    va_end(args);

    g_warning("%s", message);
    nm_vpn_service_plugin_failure(NM_VPN_SERVICE_PLUGIN(self), reason);
}

static guint
netmask_to_prefix(const char *netmask)
{
    struct in_addr addr;
    guint32 host_order;
    guint prefix = 0;

    if (netmask == NULL || inet_pton(AF_INET, netmask, &addr) != 1)
        return 32;

    host_order = ntohl(addr.s_addr);
    while (prefix < 32 && (host_order & (1u << (31 - prefix))) != 0)
        prefix++;

    return prefix;
}

static gboolean
add_route_from_spec(const char *ifname, const char *spec, GError **error)
{
    g_auto(GStrv) parts = g_strsplit(spec, "/", 2);
    guint32 dest_be;
    guint prefix;

    if (parts[0] == NULL || parts[1] == NULL) {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "invalid route spec: %s", spec);
        return FALSE;
    }
    if (!snx_ipv4_to_nm_u32(parts[0], &dest_be, error))
        return FALSE;
    prefix = (guint) g_ascii_strtoull(parts[1], NULL, 10);

    return snx_netlink_route_add(ifname, dest_be, (guint8) prefix, 0, error);
}

static gboolean
string_array_contains(const GPtrArray *array, const char *needle, gboolean ignore_case)
{
    if (array == NULL || needle == NULL)
        return FALSE;

    for (guint i = 0; i < array->len; i++) {
        const char *value = g_ptr_array_index(array, i);

        if (ignore_case ? g_ascii_strcasecmp(value, needle) == 0 : g_strcmp0(value, needle) == 0)
            return TRUE;
    }

    return FALSE;
}

static char *
canonical_domain_for_compare(const char *domain)
{
    char *copy;
    char *trimmed;
    gsize len;

    if (domain == NULL)
        return NULL;

    copy = g_strdup(domain);
    trimmed = g_strstrip(copy);
    if (g_str_has_prefix(trimmed, "~"))
        trimmed++;

    len = strlen(trimmed);
    while (len > 0 && trimmed[len - 1] == '.')
        trimmed[--len] = '\0';

    if (*trimmed == '\0') {
        g_free(copy);
        return NULL;
    }

    {
        char *result = g_strdup(trimmed);
        g_free(copy);
        return result;
    }
}

static gboolean
domain_array_contains(const GPtrArray *array, const char *needle)
{
    g_autofree char *canonical_needle = canonical_domain_for_compare(needle);

    if (array == NULL || canonical_needle == NULL)
        return FALSE;

    for (guint i = 0; i < array->len; i++) {
        g_autofree char *canonical_value = canonical_domain_for_compare(g_ptr_array_index(array, i));

        if (canonical_value != NULL && g_ascii_strcasecmp(canonical_value, canonical_needle) == 0)
            return TRUE;
    }

    return FALSE;
}

static void
append_dns_servers(GPtrArray *out, const GPtrArray *servers, const GPtrArray *ignored)
{
    if (servers == NULL)
        return;

    for (guint i = 0; i < servers->len; i++) {
        const char *server = g_ptr_array_index(servers, i);

        if (!string_array_contains(ignored, server, FALSE) && !string_array_contains(out, server, FALSE))
            g_ptr_array_add(out, g_strdup(server));
    }
}

static void
append_search_domains(GPtrArray *out, const GPtrArray *domains, const GPtrArray *ignored)
{
    if (domains == NULL)
        return;

    for (guint i = 0; i < domains->len; i++) {
        const char *domain = g_ptr_array_index(domains, i);

        if (!domain_array_contains(ignored, domain) && !domain_array_contains(out, domain))
            g_ptr_array_add(out, g_strdup(domain));
    }
}

static GPtrArray *
collect_dns_servers(const SnxConfig *config, const SnxSslHelloReply *hello_reply)
{
    GPtrArray *servers = g_ptr_array_new_with_free_func(g_free);

    append_dns_servers(servers, hello_reply->dns_servers, config->ignore_dns_servers);
    append_dns_servers(servers, config->dns_servers, config->ignore_dns_servers);

    return servers;
}

static GPtrArray *
collect_search_domains(const SnxConfig *config, const SnxSslHelloReply *hello_reply)
{
    GPtrArray *domains = g_ptr_array_new_with_free_func(g_free);

    append_search_domains(domains, hello_reply->search_domains, config->ignore_search_domains);
    append_search_domains(domains, config->search_domains, config->ignore_search_domains);

    return domains;
}

static void
append_dns_route_specs(GPtrArray *specs, const GPtrArray *servers, const GPtrArray *ignored)
{
    if (servers == NULL)
        return;

    for (guint i = 0; i < servers->len; i++) {
        const char *server = g_ptr_array_index(servers, i);
        g_autofree char *spec = NULL;

        if (string_array_contains(ignored, server, FALSE))
            continue;

        spec = g_strdup_printf("%s/32", server);
        if (!string_array_contains(specs, spec, FALSE))
            g_ptr_array_add(specs, g_steal_pointer(&spec));
    }
}

static void
append_private_dns_subnet_route_specs(GPtrArray *specs, const GPtrArray *servers, const GPtrArray *ignored)
{
    if (servers == NULL)
        return;

    for (guint i = 0; i < servers->len; i++) {
        const char *server = g_ptr_array_index(servers, i);
        g_autofree char *spec = NULL;

        if (string_array_contains(ignored, server, FALSE))
            continue;

        spec = snx_ip4_private_subnet_route_for_host(server);
        if (spec != NULL && !string_array_contains(specs, spec, FALSE))
            g_ptr_array_add(specs, g_steal_pointer(&spec));
    }
}

/* Builds the list of "a.b.c.d/N" route specs this connection should route
 * through the tunnel: the gateway-provided ranges (unless the user asked
 * for the default route or disabled routing entirely), inferred private
 * subnets for split-DNS gateways that only provide DNS hosts, host routes for
 * the DNS servers used by the VPN, plus any explicit add-routes. Shared
 * between the netlink configuration step and the Ip4Config reported to
 * NetworkManager, so both always agree. */
static GPtrArray *
collect_route_specs(const SnxConfig *config, const SnxSslHelloReply *hello_reply)
{
    GPtrArray *specs = g_ptr_array_new_with_free_func(g_free);
    guint i;

    if (!config->no_routing && !config->default_route && hello_reply->ranges != NULL) {
        for (i = 0; i < hello_reply->ranges->len; i++) {
            SnxNetworkRange *range = g_ptr_array_index(hello_reply->ranges, i);
            g_autoptr(GPtrArray) cidrs = snx_ip4_range_to_cidrs(range->from_be, range->to_be);
            guint j;

            for (j = 0; j < cidrs->len; j++)
                g_ptr_array_add(specs, g_strdup(g_ptr_array_index(cidrs, j)));
        }
    }

    if (!config->no_routing && !config->default_route) {
        if (config->set_routing_domains && hello_reply->search_domains != NULL && hello_reply->search_domains->len > 0) {
            append_private_dns_subnet_route_specs(specs, hello_reply->dns_servers, config->ignore_dns_servers);
            append_private_dns_subnet_route_specs(specs, config->dns_servers, config->ignore_dns_servers);
        }
        append_dns_route_specs(specs, hello_reply->dns_servers, config->ignore_dns_servers);
        append_dns_route_specs(specs, config->dns_servers, config->ignore_dns_servers);
    }

    if (config->add_routes != NULL) {
        for (i = 0; i < config->add_routes->len; i++)
            g_ptr_array_add(specs, g_strdup(g_ptr_array_index(config->add_routes, i)));
    }

    return specs;
}

static gboolean
configure_interface(SnxVpnPlugin *self, const char *tun_name, const SnxSslHelloReply *hello_reply, GError **error)
{
    guint32 addr_be;
    guint prefix = netmask_to_prefix(hello_reply->subnet_mask);
    g_autoptr(GPtrArray) route_specs = NULL;
    guint i;

    if (!snx_netlink_link_up(tun_name, self->config.mtu, error))
        return FALSE;

    if (!snx_ipv4_to_nm_u32(hello_reply->assigned_ip, &addr_be, error))
        return FALSE;
    if (!snx_netlink_addr_add(tun_name, addr_be, prefix, error))
        return FALSE;

    if (self->config.default_route) {
        /* Adding a tunnel-wide 0.0.0.0/0 route replaces the system's
         * existing default route (same destination/table key). Without an
         * explicit exception route for the gateway's own IP via the
         * *original* path first, the tunnel's own TCP connection to that
         * gateway would immediately start trying to route through the
         * tunnel it depends on, cutting itself off. */
        guint32 gateway_addr_be;
        guint32 bypass_gateway_be = 0;
        char bypass_ifname[IF_NAMESIZE] = {0};

        if (!snx_ipv4_to_nm_u32(self->gateway_ip, &gateway_addr_be, error))
            return FALSE;
        if (!snx_netlink_get_route_gateway(gateway_addr_be, &bypass_gateway_be, bypass_ifname,
                                           sizeof(bypass_ifname), error))
            return FALSE;
        if (!snx_netlink_route_add(bypass_ifname, gateway_addr_be, 32, bypass_gateway_be, error))
            return FALSE;

        self->bypass_route_active = TRUE;
        g_strlcpy(self->bypass_route_ifname, bypass_ifname, sizeof(self->bypass_route_ifname));
        self->bypass_route_dest_be = gateway_addr_be;
        self->bypass_route_gateway_be = bypass_gateway_be;

        if (!snx_netlink_route_add(tun_name, 0, 0, 0, error))
            return FALSE;
    }

    route_specs = collect_route_specs(&self->config, hello_reply);
    for (i = 0; i < route_specs->len; i++) {
        if (!add_route_from_spec(tun_name, g_ptr_array_index(route_specs, i), error))
            return FALSE;
    }

    return TRUE;
}

/* ---- packet forwarding threads ---- */

static gboolean
on_forwarding_thread_failed(gpointer user_data)
{
    SnxVpnPlugin *self = user_data;

    report_failure(self, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED,
                   "snx tunnel forwarding stopped unexpectedly, disconnecting");
    return G_SOURCE_REMOVE;
}

/* Called by a forwarding thread right before it returns. Reports the exit
 * to the main loop (which owns the NMVpnServicePlugin API) unless
 * teardown_tunnel() is the reason the thread is exiting, and reports at
 * most once even if both threads exit around the same time. */
static void
report_unexpected_thread_exit(SnxVpnPlugin *self)
{
    if (g_atomic_int_get(&self->tearing_down))
        return;
    if (!g_atomic_int_compare_and_exchange(&self->unexpected_exit_reported, FALSE, TRUE))
        return;
    g_idle_add(on_forwarding_thread_failed, self);
}

/* Both forwarding threads capture tun_fd/tunnel once at start-up rather
 * than re-reading self->tun_fd/self->tunnel on every loop iteration:
 * teardown_tunnel() (main thread) closes the fd and the tunnel connection
 * to unblock these threads' blocking calls, but does so without a lock, so
 * repeatedly re-reading the fields while it runs would be a data race even
 * though the values themselves never change during a thread's own
 * lifetime. */

static gpointer
uplink_thread_func(gpointer user_data)
{
    SnxVpnPlugin *self = user_data;
    int fd = self->tun_fd;
    int wake_fd = self->uplink_wake_fd;
    SnxSslTunnel *tunnel = self->tunnel;
    guint8 buf[2048];
    struct pollfd pfds[2] = {
        { .fd = fd, .events = POLLIN },
        { .fd = wake_fd, .events = POLLIN },
    };

    for (;;) {
        ssize_t n;
        g_autoptr(GError) error = NULL;

        /* wake_fd may be -1 if eventfd() failed at connect time; poll()
         * ignores negative fds in the set (revents left 0), so this just
         * falls back to blocking on tun_fd alone in that rare case. */
        if (poll(pfds, G_N_ELEMENTS(pfds), -1) < 0) {
            if (errno == EINTR)
                continue;
            g_warning("snx uplink: poll failed, stopping: %s", g_strerror(errno));
            break;
        }
        if (pfds[1].revents != 0) {
            g_message("snx uplink: woken for teardown");
            break;
        }
        if (pfds[0].revents == 0)
            continue;

        n = read(fd, buf, sizeof(buf));
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN)
                continue;
            g_warning("snx uplink: tun read failed, stopping: %s", g_strerror(errno));
            break;
        }
        if (n == 0) {
            g_warning("snx uplink: tun read returned EOF, stopping");
            break;
        }

        if (!snx_ssl_tunnel_send_data(tunnel, buf, (gsize) n, &error)) {
            g_warning("snx uplink: failed to send %zd bytes to tunnel, stopping: %s", n,
                     error != NULL ? error->message : "(unknown error)");
            break;
        }
    }

    g_message("snx uplink: thread exiting");
    report_unexpected_thread_exit(self);
    return NULL;
}

static gpointer
downlink_thread_func(gpointer user_data)
{
    SnxVpnPlugin *self = user_data;
    int fd = self->tun_fd;
    SnxSslTunnel *tunnel = self->tunnel;

    for (;;) {
        g_autoptr(GError) error = NULL;
        SnxSlimPacket *packet = snx_ssl_tunnel_receive(tunnel, &error);

        if (packet == NULL) {
            g_warning("snx downlink: tunnel receive failed, stopping: %s",
                     error != NULL ? error->message : "(unknown error)");
            break;
        }

        if (packet->type == SNX_SLIM_DATA) {
            gsize len;
            const guint8 *data = g_bytes_get_data(packet->data, &len);

            if (write(fd, data, len) < 0 && errno != EAGAIN) {
                g_warning("snx downlink: tun write failed, stopping: %s", g_strerror(errno));
                snx_slim_packet_free(packet);
                break;
            }
            g_atomic_int_set(&self->keepalive_misses, 0);
        } else {
            g_autoptr(GError) parse_error = NULL;
            SnxSexpr *expr = snx_sexpr_parse(packet->control_text, &parse_error);

            if (expr != NULL) {
                if (g_strcmp0(snx_sexpr_object_name(expr), "keepalive") == 0)
                    g_atomic_int_set(&self->keepalive_misses, 0);
                snx_sexpr_free(expr);
            }
        }

        snx_slim_packet_free(packet);
    }

    g_message("snx downlink: thread exiting");
    report_unexpected_thread_exit(self);
    return NULL;
}

static gboolean
on_keepalive_tick(gpointer user_data)
{
    SnxVpnPlugin *self = user_data;
    g_autoptr(GError) error = NULL;

    if (g_atomic_int_get(&self->keepalive_misses) >= SNX_KEEPALIVE_MAX_MISSES) {
        self->keepalive_source_id = 0;
        report_failure(self, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED, "no response to keepalive packets, tunnel appears stuck");
        return G_SOURCE_REMOVE;
    }

    g_atomic_int_inc(&self->keepalive_misses);
    if (!snx_ssl_tunnel_send_keepalive(self->tunnel, &error)) {
        self->keepalive_source_id = 0;
        report_failure(self, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED, "failed to send keepalive: %s", error->message);
        return G_SOURCE_REMOVE;
    }

    return G_SOURCE_CONTINUE;
}

static void
teardown_tunnel(SnxVpnPlugin *self)
{
    /* Set before unblocking the forwarding threads below, so they see it
     * once their blocking read/receive calls fail and know not to
     * self-report this as an unexpected exit. */
    g_atomic_int_set(&self->tearing_down, TRUE);

    if (self->bypass_route_active) {
        g_autoptr(GError) route_error = NULL;

        if (!snx_netlink_route_del(self->bypass_route_ifname, self->bypass_route_dest_be, 32,
                                   self->bypass_route_gateway_be, &route_error))
            g_warning("snx: failed to remove gateway bypass route on %s: %s", self->bypass_route_ifname,
                     route_error != NULL ? route_error->message : "(unknown error)");
        self->bypass_route_active = FALSE;
    }

    if (self->keepalive_source_id != 0) {
        g_source_remove(self->keepalive_source_id);
        self->keepalive_source_id = 0;
    }

    /* Unblock the forwarding threads' blocking reads/poll before joining
     * them. shutdown()ing the tunnel socket (inside
     * snx_ssl_tunnel_close()) reliably wakes the downlink thread; closing
     * tun_fd is not a reliable enough wakeup for the uplink thread's
     * poll() on the same fd from another thread, hence uplink_wake_fd. */
    if (self->tunnel != NULL)
        snx_ssl_tunnel_close(self->tunnel);
    if (self->uplink_wake_fd >= 0) {
        guint64 one = 1;

        if (write(self->uplink_wake_fd, &one, sizeof(one)) < 0 && errno != EAGAIN)
            g_warning("snx: failed to signal uplink teardown eventfd: %s", g_strerror(errno));
    }
    if (self->tun_fd >= 0) {
        close(self->tun_fd);
        self->tun_fd = -1;
    }

    if (self->downlink_thread != NULL) {
        g_thread_join(self->downlink_thread);
        self->downlink_thread = NULL;
    }
    if (self->uplink_thread != NULL) {
        g_thread_join(self->uplink_thread);
        self->uplink_thread = NULL;
    }
    if (self->uplink_wake_fd >= 0) {
        close(self->uplink_wake_fd);
        self->uplink_wake_fd = -1;
    }

    g_clear_pointer(&self->tunnel, snx_ssl_tunnel_free);
    g_clear_pointer(&self->tun_name, g_free);

    /* Re-arm for the next connection attempt. */
    g_atomic_int_set(&self->tearing_down, FALSE);
    g_atomic_int_set(&self->unexpected_exit_reported, FALSE);
}

static void
start_forwarding(SnxVpnPlugin *self, guint keepalive_seconds)
{
    g_atomic_int_set(&self->keepalive_misses, 0);

    self->uplink_wake_fd = eventfd(0, EFD_CLOEXEC);
    if (self->uplink_wake_fd < 0)
        g_warning("snx: eventfd() failed, uplink teardown may be slow: %s", g_strerror(errno));

    self->uplink_thread = g_thread_new("snx-uplink", uplink_thread_func, self);
    self->downlink_thread = g_thread_new("snx-downlink", downlink_thread_func, self);

    if (keepalive_seconds > 0)
        self->keepalive_source_id = g_timeout_add_seconds(keepalive_seconds, on_keepalive_tick, self);
}

/* ---- final connect step: TUN device, netlink, NM Ip4Config ---- */

static void
finish_connect(SnxVpnPlugin *self, const SnxSslHelloReply *hello_reply)
{
    g_autoptr(GError) error = NULL;
    g_autoptr(GPtrArray) route_specs = NULL;
    g_autoptr(GPtrArray) routes = NULL;
    g_autoptr(GPtrArray) dns_servers = NULL;
    g_autoptr(GPtrArray) search_domains = NULL;
    g_autoptr(GVariant) ip4_config = NULL;
    g_autoptr(GVariant) config = NULL;
    GVariantBuilder config_builder;
    guint prefix = netmask_to_prefix(hello_reply->subnet_mask);
    guint32 gateway_be = 0;

    if (self->gateway_ip == NULL || !snx_ipv4_to_nm_u32(self->gateway_ip, &gateway_be, &error)) {
        report_failure(self, NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG, "no VPN gateway address available: %s",
                       error != NULL ? error->message : "(none)");
        teardown_tunnel(self);
        return;
    }

    route_specs = collect_route_specs(&self->config, hello_reply);
    routes = snx_ip4_routes_from_strings(route_specs, &error);
    if (routes == NULL) {
        report_failure(self, NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG, "invalid route configuration: %s", error->message);
        teardown_tunnel(self);
        return;
    }

    dns_servers = collect_dns_servers(&self->config, hello_reply);
    search_domains = collect_search_domains(&self->config, hello_reply);

    ip4_config = snx_ip4_config_new(hello_reply->assigned_ip,
                                    prefix,
                                    routes,
                                    dns_servers,
                                    search_domains,
                                    !self->config.default_route,
                                    self->config.dns_priority,
                                    self->config.set_routing_domains,
                                    &error);
    if (ip4_config == NULL) {
        report_failure(self, NM_VPN_PLUGIN_FAILURE_BAD_IP_CONFIG, "invalid IPv4 configuration: %s", error->message);
        teardown_tunnel(self);
        return;
    }

    g_variant_builder_init(&config_builder, G_VARIANT_TYPE("a{sv}"));
    g_variant_builder_add(&config_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_TUNDEV, g_variant_new_string(self->tun_name));
    g_variant_builder_add(&config_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_MTU, g_variant_new_uint32(self->config.mtu));
    g_variant_builder_add(&config_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_HAS_IP4, g_variant_new_boolean(TRUE));
    g_variant_builder_add(&config_builder, "{sv}", NM_VPN_PLUGIN_CONFIG_EXT_GATEWAY, g_variant_new_uint32(gateway_be));
    config = g_variant_ref_sink(g_variant_builder_end(&config_builder));

    nm_vpn_service_plugin_set_config(NM_VPN_SERVICE_PLUGIN(self), config);
    nm_vpn_service_plugin_set_ip4_config(NM_VPN_SERVICE_PLUGIN(self), ip4_config);

    start_forwarding(self, self->config.no_keepalive ? 0 : hello_reply->keepalive_seconds);
}

/* ---- async step 2: open the SSL tunnel and configure networking ---- */

typedef struct {
    char *server_name;
    guint16 tcpt_port;
    gboolean ignore_server_cert;
    char *active_key;
} TunnelTaskData;

static void
tunnel_task_data_free(TunnelTaskData *data)
{
    g_free(data->server_name);
    g_free(data->active_key);
    g_free(data);
}

static void
free_hello_reply_boxed(SnxSslHelloReply *reply)
{
    snx_ssl_hello_reply_clear(reply);
    g_free(reply);
}

static void
tunnel_thread_func(GTask *task, gpointer source_object, gpointer task_data, GCancellable *cancellable)
{
    SnxVpnPlugin *self = source_object;
    TunnelTaskData *data = task_data;
    SnxSslHelloReply *hello_reply = g_new0(SnxSslHelloReply, 1);
    SnxSslTunnel *tunnel;
    GError *error = NULL;
    char *tun_name = NULL;
    const char *if_name_hint;
    int fd;

    (void) cancellable;

    tunnel = snx_ssl_tunnel_connect(data->server_name, data->tcpt_port, data->ignore_server_cert, data->active_key,
                                    hello_reply, &error);
    if (tunnel == NULL) {
        g_free(hello_reply);
        g_task_return_error(task, error);
        return;
    }

    if_name_hint = self->config.if_name != NULL && *self->config.if_name != '\0' ? self->config.if_name : "snx-tun";
    fd = snx_tun_create(if_name_hint, &tun_name, &error);
    if (fd < 0) {
        snx_ssl_hello_reply_clear(hello_reply);
        g_free(hello_reply);
        snx_ssl_tunnel_free(tunnel);
        g_task_return_error(task, error);
        return;
    }

    if (!configure_interface(self, tun_name, hello_reply, &error)) {
        close(fd);
        g_free(tun_name);
        snx_ssl_hello_reply_clear(hello_reply);
        g_free(hello_reply);
        snx_ssl_tunnel_free(tunnel);
        g_task_return_error(task, error);
        return;
    }

    /* A Disconnect() or a fresh Connect() that arrived while the (slow)
     * work above was running already tore down old state and cancelled
     * this task; if so, undo everything instead of publishing it, so
     * teardown_tunnel() never gets bypassed by state arriving after it ran. */
    if (g_task_return_error_if_cancelled(task)) {
        close(fd);
        g_free(tun_name);
        snx_ssl_hello_reply_clear(hello_reply);
        g_free(hello_reply);
        snx_ssl_tunnel_free(tunnel);
        return;
    }

    /* Hand ownership to the plugin now. Safe without extra locking: no
     * other code touches these fields until the GTask completion callback
     * below runs on the main thread, strictly after this point. */
    self->tunnel = tunnel;
    self->tun_fd = fd;
    self->tun_name = tun_name;

    g_task_return_pointer(task, hello_reply, (GDestroyNotify) free_hello_reply_boxed);
}

static void
on_tunnel_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    SnxVpnPlugin *self = SNX_VPN_PLUGIN(source);
    g_autoptr(GError) error = NULL;
    SnxSslHelloReply *hello_reply = g_task_propagate_pointer(G_TASK(result), &error);

    (void) user_data;

    if (hello_reply == NULL) {
        if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            report_failure(self, NM_VPN_PLUGIN_FAILURE_CONNECT_FAILED, "tunnel setup failed: %s", error->message);
        return;
    }

    finish_connect(self, hello_reply);
    free_hello_reply_boxed(hello_reply);
}

static void
start_tunnel(SnxVpnPlugin *self, const char *active_key)
{
    TunnelTaskData *data = g_new0(TunnelTaskData, 1);
    GTask *task;

    data->server_name = g_strdup(self->config.server_name);
    data->tcpt_port = self->tcpt_port;
    data->ignore_server_cert = self->config.ignore_server_cert;
    data->active_key = g_strdup(active_key);

    task = g_task_new(self, self->cancellable, on_tunnel_done, NULL);
    g_task_set_task_data(task, data, (GDestroyNotify) tunnel_task_data_free);
    g_task_run_in_thread(task, tunnel_thread_func);
    g_object_unref(task);
}

/* ---- async step 1: CCC gateway discovery + authentication / MFA ---- */

typedef struct {
    SnxCccOptions ccc_options; /* server_name/ignore_server_cert borrowed from config, valid for the task's lifetime */
    char *login_type;
    char *username;
    char *password;
    gboolean is_challenge;    /* TRUE => password holds the MFA/challenge code, not the login password */
    char *session_id;          /* only used when is_challenge */
} AuthTaskData;

static void
auth_task_data_free(AuthTaskData *data)
{
    g_free(data->login_type);
    g_free(data->username);
    g_free(data->password);
    g_free(data->session_id);
    g_free(data);
}

typedef struct {
    SnxGatewayInfo *gateway_info; /* NULL when reusing a cached tcpt_port on the challenge path */
    SnxAuthResult *auth_result;
} AuthStepResult;

static void
auth_step_result_free(AuthStepResult *result)
{
    g_clear_pointer(&result->gateway_info, snx_gateway_info_free);
    g_clear_pointer(&result->auth_result, snx_auth_result_free);
    g_free(result);
}

static void
auth_thread_func(GTask *task, gpointer source_object, gpointer task_data, GCancellable *cancellable)
{
    AuthTaskData *data = task_data;
    AuthStepResult *result = g_new0(AuthStepResult, 1);
    GError *error = NULL;

    (void) source_object;
    (void) cancellable;

    if (!data->is_challenge) {
        if (!snx_ccc_get_gateway_info(&data->ccc_options, &result->gateway_info, &error)) {
            auth_step_result_free(result);
            g_task_return_error(task, error);
            return;
        }

        if (!snx_ccc_authenticate(&data->ccc_options, data->login_type, data->username, data->password,
                                  &result->auth_result, &error)) {
            auth_step_result_free(result);
            g_task_return_error(task, error);
            return;
        }
    } else {
        if (!snx_ccc_challenge_code(&data->ccc_options, data->session_id, data->password, &result->auth_result,
                                    &error)) {
            auth_step_result_free(result);
            g_task_return_error(task, error);
            return;
        }
    }

    g_task_return_pointer(task, result, (GDestroyNotify) auth_step_result_free);
}

static void
on_auth_done(GObject *source, GAsyncResult *result_async, gpointer user_data)
{
    SnxVpnPlugin *self = SNX_VPN_PLUGIN(source);
    g_autoptr(GError) error = NULL;
    AuthStepResult *step = g_task_propagate_pointer(G_TASK(result_async), &error);
    SnxAuthResult *auth_result;

    (void) user_data;

    if (step == NULL) {
        if (!g_error_matches(error, G_IO_ERROR, G_IO_ERROR_CANCELLED))
            report_failure(self, NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED, "authentication request failed: %s",
                           error->message);
        return;
    }

    if (step->gateway_info != NULL) {
        self->tcpt_port = (guint16) step->gateway_info->tcpt_port;
        g_clear_pointer(&self->gateway_ip, g_free);
        self->gateway_ip = g_strdup(step->gateway_info->server_ip);
    }

    auth_result = step->auth_result;

    if (g_strcmp0(auth_result->authn_status, "continue") == 0) {
        const char *hints[] = {"x-snx-challenge", NULL};
        const char *message = auth_result->prompt != NULL && *auth_result->prompt != '\0' ? auth_result->prompt
                                                                                          : "Enter the verification code";

        g_clear_pointer(&self->ccc_session_id, g_free);
        self->ccc_session_id = g_strdup(auth_result->session_id);
        self->awaiting_challenge = TRUE;

        nm_vpn_service_plugin_secrets_required(NM_VPN_SERVICE_PLUGIN(self), message, hints);
        auth_step_result_free(step);
        return;
    }

    if (g_strcmp0(auth_result->authn_status, "done") != 0 || !auth_result->is_authenticated ||
        auth_result->active_key == NULL) {
        const char *reason = auth_result->error_message != NULL ? auth_result->error_message : "authentication failed";

        report_failure(self, NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED, "%s", reason);
        auth_step_result_free(step);
        return;
    }

    start_tunnel(self, auth_result->active_key);
    auth_step_result_free(step);
}

static void
start_authenticate(SnxVpnPlugin *self)
{
    AuthTaskData *data = g_new0(AuthTaskData, 1);
    GTask *task;

    data->ccc_options.server_name = g_strdup(self->config.server_name);
    data->ccc_options.ignore_server_cert = self->config.ignore_server_cert;
    data->login_type = g_strdup(self->config.login_type);
    data->username = g_strdup(self->username);
    data->password = g_strdup(self->password);
    data->is_challenge = FALSE;

    task = g_task_new(self, self->cancellable, on_auth_done, NULL);
    g_task_set_task_data(task, data, (GDestroyNotify) auth_task_data_free);
    g_task_run_in_thread(task, auth_thread_func);
    g_object_unref(task);
}

static void
start_challenge(SnxVpnPlugin *self, const char *code)
{
    AuthTaskData *data = g_new0(AuthTaskData, 1);
    GTask *task;

    data->ccc_options.server_name = g_strdup(self->config.server_name);
    data->ccc_options.ignore_server_cert = self->config.ignore_server_cert;
    data->password = g_strdup(code);
    data->is_challenge = TRUE;
    data->session_id = g_strdup(self->ccc_session_id);

    task = g_task_new(self, self->cancellable, on_auth_done, NULL);
    g_task_set_task_data(task, data, (GDestroyNotify) auth_task_data_free);
    g_task_run_in_thread(task, auth_thread_func);
    g_object_unref(task);
}

/* ---- NMVpnServicePlugin vfuncs ---- */

/* Cancels any in-flight async auth/tunnel step, so it cannot publish state
 * to self (finish_connect()/start_forwarding(), or a chained start_tunnel()
 * from on_auth_done()) after the caller's teardown_tunnel() has already run.
 * Must run before teardown_tunnel() in every caller. */
static void
cancel_inflight_task(SnxVpnPlugin *self)
{
    if (self->cancellable != NULL) {
        g_cancellable_cancel(self->cancellable);
        g_clear_object(&self->cancellable);
    }
}

static void
reset_plugin_state(SnxVpnPlugin *self)
{
    cancel_inflight_task(self);
    teardown_tunnel(self);
    snx_config_clear(&self->config);
    g_clear_pointer(&self->username, g_free);
    g_clear_pointer(&self->password, g_free);
    g_clear_pointer(&self->ccc_session_id, g_free);
    g_clear_pointer(&self->gateway_ip, g_free);
    self->awaiting_challenge = FALSE;
    self->tcpt_port = 0;
}

static gboolean
snx_vpn_connect(NMVpnServicePlugin *plugin, NMConnection *connection, GError **error)
{
    SnxVpnPlugin *self = SNX_VPN_PLUGIN(plugin);
    NMSettingVpn *s_vpn;
    const char *password;

    reset_plugin_state(self);
    self->cancellable = g_cancellable_new();

    snx_config_init(&self->config);
    if (!snx_config_from_connection(&self->config, connection, error)) {
        nm_vpn_service_plugin_failure(plugin, NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
        return FALSE;
    }

    if (!snx_config_validate_for_connect(&self->config, error)) {
        nm_vpn_service_plugin_failure(plugin, NM_VPN_PLUGIN_FAILURE_LOGIN_FAILED);
        return FALSE;
    }

    self->username = g_strdup(self->config.user_name != NULL ? self->config.user_name : "");

    s_vpn = nm_connection_get_setting_vpn(connection);
    password = s_vpn != NULL ? nm_setting_vpn_get_secret(s_vpn, "password") : NULL;
    self->password = g_strdup(password != NULL ? password : "");

    start_authenticate(self);

    return TRUE;
}

static gboolean
snx_vpn_connect_interactive(NMVpnServicePlugin *plugin,
                            NMConnection *connection,
                            GVariant *details,
                            GError **error)
{
    (void) details;
    return snx_vpn_connect(plugin, connection, error);
}

static gboolean
snx_vpn_need_secrets(NMVpnServicePlugin *plugin,
                     NMConnection *connection,
                     const char **setting_name,
                     GError **error)
{
    SnxConfig config;
    gboolean needs_password;

    (void) plugin;

    *setting_name = NULL;

    snx_config_init(&config);
    if (!snx_config_from_connection(&config, connection, error)) {
        snx_config_clear(&config);
        return FALSE;
    }

    needs_password = snx_config_needs_password(&config);
    snx_config_clear(&config);

    if (!needs_password) {
        *setting_name = NULL;
        return FALSE;
    }

    *setting_name = NM_SETTING_VPN_SETTING_NAME;
    return TRUE;
}

static gboolean
snx_vpn_new_secrets(NMVpnServicePlugin *plugin, NMConnection *connection, GError **error)
{
    SnxVpnPlugin *self = SNX_VPN_PLUGIN(plugin);
    NMSettingVpn *s_vpn = nm_connection_get_setting_vpn(connection);
    const char *code = s_vpn != NULL ? nm_setting_vpn_get_secret(s_vpn, "password") : NULL;

    if (!self->awaiting_challenge || code == NULL || *code == '\0') {
        g_set_error(error, SNX_ERROR, SNX_ERROR_INVALID_CONFIG, "no verification code was provided");
        return FALSE;
    }

    self->awaiting_challenge = FALSE;
    start_challenge(self, code);
    return TRUE;
}

static gboolean
snx_vpn_disconnect(NMVpnServicePlugin *plugin, GError **error)
{
    SnxVpnPlugin *self = SNX_VPN_PLUGIN(plugin);

    (void) error;
    /* Without this, a Connect() still completing its async auth/tunnel
     * steps when Disconnect() arrives can finish afterwards and publish a
     * tunnel through a NULL self->tunnel/tun_fd that teardown_tunnel()
     * below already cleared, crashing the forwarding threads and
     * resurrecting a connection NetworkManager already considers gone. */
    /* Do NOT call nm_vpn_service_plugin_disconnect() here: that public API
     * function is what invokes this vfunc (via
     * NM_VPN_SERVICE_PLUGIN_GET_CLASS(plugin)->disconnect()) and already
     * transitions the plugin to STOPPED once this function returns. Calling
     * it again would recurse back into the same function while it's still
     * on the call stack. */
    cancel_inflight_task(self);
    teardown_tunnel(self);
    return TRUE;
}

static void
snx_vpn_plugin_finalize(GObject *object)
{
    SnxVpnPlugin *self = SNX_VPN_PLUGIN(object);

    reset_plugin_state(self);

    G_OBJECT_CLASS(snx_vpn_plugin_parent_class)->finalize(object);
}

static void
snx_vpn_plugin_class_init(SnxVpnPluginClass *klass)
{
    NMVpnServicePluginClass *plugin_class = NM_VPN_SERVICE_PLUGIN_CLASS(klass);
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    plugin_class->connect = snx_vpn_connect;
    plugin_class->connect_interactive = snx_vpn_connect_interactive;
    plugin_class->need_secrets = snx_vpn_need_secrets;
    plugin_class->new_secrets = snx_vpn_new_secrets;
    plugin_class->disconnect = snx_vpn_disconnect;

    object_class->finalize = snx_vpn_plugin_finalize;
}

static void
snx_vpn_plugin_init(SnxVpnPlugin *plugin)
{
    plugin->tun_fd = -1;
    plugin->uplink_wake_fd = -1;
}

static gboolean
snx_vpn_plugin_initable_init(GInitable *initable, GCancellable *cancellable, GError **error)
{
    if (initable_parent_iface == NULL || initable_parent_iface->init == NULL)
        return TRUE;

    return initable_parent_iface->init(initable, cancellable, error);
}

static void
snx_vpn_plugin_initable_iface_init(GInitableIface *iface)
{
    initable_parent_iface = g_type_interface_peek_parent(iface);
    iface->init = snx_vpn_plugin_initable_init;
}

static void
on_plugin_quit(NMVpnServicePlugin *plugin, gpointer user_data)
{
    (void) plugin;
    g_main_loop_quit(user_data);
}

typedef struct {
    GMainLoop *loop;
    SnxVpnPlugin *self;
} SnxSignalContext;

/* SIGTERM/SIGINT are a second, independent way this process can be told to
 * stop, alongside the D-Bus Disconnect() -> snx_vpn_disconnect() path. If a
 * tunnel/TUN device is still up when one of these arrives, tear it down here
 * too -- otherwise the process would exit without closing tun_fd, leaving a
 * "snx-tun" device that makes the next connection attempt's TUNSETIFF fail
 * with EBUSY. Safe to call unconditionally: teardown_tunnel() is a no-op on
 * an already-torn-down plugin (tun_fd is -1, tunnel/threads are NULL). */
static gboolean
on_term_signal(gpointer user_data)
{
    SnxSignalContext *ctx = user_data;

    cancel_inflight_task(ctx->self);
    teardown_tunnel(ctx->self);
    g_main_loop_quit(ctx->loop);
    return G_SOURCE_REMOVE;
}

static NMVpnServicePlugin *
snx_vpn_plugin_new(const char *bus_name, GError **error)
{
    return g_initable_new(snx_vpn_plugin_get_type(),
                          NULL,
                          error,
                          NM_VPN_SERVICE_PLUGIN_DBUS_SERVICE_NAME,
                          bus_name,
                          NM_VPN_SERVICE_PLUGIN_DBUS_WATCH_PEER,
                          TRUE,
                          NULL);
}

int
main(int argc, char **argv)
{
    const char *bus_name = SNX_DBUS_SERVICE_NAME;
    g_autoptr(GMainLoop) loop = NULL;
    g_autoptr(NMVpnServicePlugin) plugin = NULL;
    g_autoptr(GError) error = NULL;

    for (int i = 1; i < argc; i++) {
        if (g_str_equal(argv[i], "--bus-name") && i + 1 < argc) {
            bus_name = argv[++i];
        } else if (g_str_equal(argv[i], "--help")) {
            g_print("Usage: %s [--bus-name NAME]\n", argv[0]);
            return 0;
        }
    }

    loop = g_main_loop_new(NULL, FALSE);
    plugin = snx_vpn_plugin_new(bus_name, &error);
    if (plugin == NULL) {
        g_printerr("failed to create SNX VPN service plugin: %s\n",
                   error != NULL ? error->message : "unknown error");
        return 1;
    }

    SnxSignalContext sig_ctx = { .loop = loop, .self = SNX_VPN_PLUGIN(plugin) };

    g_signal_connect(plugin, "quit", G_CALLBACK(on_plugin_quit), loop);
    g_unix_signal_add(SIGTERM, on_term_signal, &sig_ctx);
    g_unix_signal_add(SIGINT, on_term_signal, &sig_ctx);

    g_main_loop_run(loop);

    if (error != NULL) {
        g_printerr("%s\n", error->message);
        return 1;
    }

    return 0;
}
