/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include <NetworkManager.h>
#include <glib.h>
#include <unistd.h>

static void
test_load_editor_plugin(gconstpointer user_data)
{
    const char *path = user_data;
    g_autoptr(NMVpnEditorPlugin) plugin = NULL;
    g_autoptr(GError) error = NULL;
    g_autofree char *name = NULL;
    g_autofree char *description = NULL;
    g_autofree char *service = NULL;
    NMVpnEditorPluginCapability capabilities;

    plugin = nm_vpn_editor_plugin_load_from_file(path,
                                                 "org.freedesktop.NetworkManager.snx",
                                                 (int) getuid(),
                                                 NULL,
                                                 NULL,
                                                 &error);
    g_assert_no_error(error);
    g_assert_nonnull(plugin);

    g_object_get(plugin,
                 NM_VPN_EDITOR_PLUGIN_NAME,
                 &name,
                 NM_VPN_EDITOR_PLUGIN_DESCRIPTION,
                 &description,
                 NM_VPN_EDITOR_PLUGIN_SERVICE,
                 &service,
                 NULL);
    g_assert_cmpstr(name, ==, "Check Point SNX/Remote Access");
    g_assert_cmpstr(description, ==, "Connect to Check Point SNX and Remote Access VPN gateways");
    g_assert_cmpstr(service, ==, "org.freedesktop.NetworkManager.snx");

    capabilities = nm_vpn_editor_plugin_get_capabilities(plugin);
    g_assert_true((capabilities & NM_VPN_EDITOR_PLUGIN_CAPABILITY_NO_EDITOR) == 0);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_assert_cmpint(argc, ==, 2);
    g_test_add_data_func("/editor-plugin/load", argv[1], test_load_editor_plugin);
    return g_test_run();
}
