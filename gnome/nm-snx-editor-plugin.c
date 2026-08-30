/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "nm-snx-editor.h"
#include "snx-service-name.h"

#include <NetworkManager.h>
#include <glib-object.h>
#include <gmodule.h>

#define SNX_EDITOR_PLUGIN_NAME "Check Point SNX/Remote Access"
#define SNX_EDITOR_PLUGIN_DESCRIPTION "Connect to Check Point SNX and Remote Access VPN gateways"

typedef struct {
    GObject parent;
} SnxEditorPlugin;

typedef struct {
    GObjectClass parent_class;
} SnxEditorPluginClass;

static void snx_editor_plugin_iface_init(NMVpnEditorPluginInterface *iface);

G_DEFINE_TYPE_WITH_CODE(SnxEditorPlugin,
                        snx_editor_plugin,
                        G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR_PLUGIN, snx_editor_plugin_iface_init))

enum {
    PROP_0,
    PROP_NAME,
    PROP_DESCRIPTION,
    PROP_SERVICE,
    N_PROPERTIES,
};

static GParamSpec *properties[N_PROPERTIES];

static void
snx_editor_plugin_get_property(GObject *object, guint property_id, GValue *value, GParamSpec *pspec)
{
    (void) object;

    switch (property_id) {
    case PROP_NAME:
        g_value_set_string(value, SNX_EDITOR_PLUGIN_NAME);
        break;
    case PROP_DESCRIPTION:
        g_value_set_string(value, SNX_EDITOR_PLUGIN_DESCRIPTION);
        break;
    case PROP_SERVICE:
        g_value_set_string(value, SNX_DBUS_SERVICE_NAME);
        break;
    default:
        G_OBJECT_WARN_INVALID_PROPERTY_ID(object, property_id, pspec);
        break;
    }
}

static NMVpnEditor *
snx_editor_plugin_get_editor(NMVpnEditorPlugin *plugin, NMConnection *connection, GError **error)
{
    (void) plugin;

    return snx_editor_new(connection, error);
}

static NMVpnEditorPluginCapability
snx_editor_plugin_get_capabilities(NMVpnEditorPlugin *plugin)
{
    (void) plugin;
    return NM_VPN_EDITOR_PLUGIN_CAPABILITY_NONE;
}

static NMConnection *
snx_editor_plugin_import(NMVpnEditorPlugin *plugin, const char *path, GError **error)
{
    (void) plugin;
    (void) path;

    g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED, "SNX import is not implemented yet");
    return NULL;
}

static gboolean
snx_editor_plugin_export(NMVpnEditorPlugin *plugin, const char *path, NMConnection *connection, GError **error)
{
    (void) plugin;
    (void) path;
    (void) connection;

    g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_FAILED, "SNX export is not implemented yet");
    return FALSE;
}

static char *
snx_editor_plugin_get_suggested_filename(NMVpnEditorPlugin *plugin, NMConnection *connection)
{
    (void) plugin;
    (void) connection;
    return g_strdup("snx.conf");
}

static void
snx_editor_plugin_iface_init(NMVpnEditorPluginInterface *iface)
{
    iface->get_editor = snx_editor_plugin_get_editor;
    iface->get_capabilities = snx_editor_plugin_get_capabilities;
    iface->import_from_file = snx_editor_plugin_import;
    iface->export_to_file = snx_editor_plugin_export;
    iface->get_suggested_filename = snx_editor_plugin_get_suggested_filename;
}

static void
snx_editor_plugin_class_init(SnxEditorPluginClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->get_property = snx_editor_plugin_get_property;

    properties[PROP_NAME] = g_param_spec_string(NM_VPN_EDITOR_PLUGIN_NAME,
                                                NM_VPN_EDITOR_PLUGIN_NAME,
                                                "Short display name",
                                                SNX_EDITOR_PLUGIN_NAME,
                                                G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    properties[PROP_DESCRIPTION] = g_param_spec_string(NM_VPN_EDITOR_PLUGIN_DESCRIPTION,
                                                       NM_VPN_EDITOR_PLUGIN_DESCRIPTION,
                                                       "Plugin description",
                                                       SNX_EDITOR_PLUGIN_DESCRIPTION,
                                                       G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);
    properties[PROP_SERVICE] = g_param_spec_string(NM_VPN_EDITOR_PLUGIN_SERVICE,
                                                   NM_VPN_EDITOR_PLUGIN_SERVICE,
                                                   "D-Bus service name",
                                                   SNX_DBUS_SERVICE_NAME,
                                                   G_PARAM_READABLE | G_PARAM_STATIC_STRINGS);

    g_object_class_install_properties(object_class, N_PROPERTIES, properties);
}

static void
snx_editor_plugin_init(SnxEditorPlugin *plugin)
{
    (void) plugin;
}

G_MODULE_EXPORT NMVpnEditorPlugin *
nm_vpn_editor_plugin_factory(GError **error)
{
    if (error != NULL)
        g_return_val_if_fail(*error == NULL, NULL);

    return NM_VPN_EDITOR_PLUGIN(g_object_new(snx_editor_plugin_get_type(), NULL));
}
