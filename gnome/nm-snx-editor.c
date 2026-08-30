/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "nm-snx-editor.h"

#include "snx-ccc.h"
#include "snx-config.h"
#include "snx-service-name.h"

#include <NetworkManager.h>
#include <gio/gio.h>
#include <gtk/gtk.h>
#include <nma-ui-utils.h>
#include <string.h>

typedef struct {
    char *if_name;
    int mtu;

    char *dns_servers;
    char *ignore_dns_servers;
    char *search_domains;
    char *ignore_search_domains;
    gboolean set_routing_domains;
    int dns_priority;
    gboolean disable_ipv6;

    gboolean default_route;
    gboolean no_routing;
    char *add_routes;
    char *ignore_routes;
    gboolean allow_forwarding;

    char *ca_cert;
    gboolean ignore_server_cert;

    gboolean no_keepalive;
    gboolean port_knock;
    gboolean ike_persist;
    int ike_lifetime;
    int ip_lease_time;
} SnxAdvancedSnapshot;

typedef struct {
    GObject parent;

    GtkWidget *widget;
    GtkWidget *advanced_dialog;
    SnxAdvancedSnapshot advanced_snapshot;

    GtkWidget *entry_server;
    GtkWidget *dropdown_tunnel_type;
    GtkWidget *dropdown_transport_type;

    GtkWidget *dropdown_login_type;
    GPtrArray *login_type_ids; /* char *, index-aligned with dropdown_login_type's model */
    GtkWidget *button_query_login_type;
    GtkWidget *login_type_popover; /* transient, error messages only */
    GtkWidget *check_use_certificate;
    GtkWidget *entry_username;
    GtkWidget *entry_password;

    GtkWidget *label_cert_type;
    GtkWidget *label_cert_path;
    GtkWidget *label_cert_id;
    GtkWidget *label_cert_password;
    GtkWidget *row_cert_type;
    GtkWidget *row_cert_path;
    GtkWidget *row_cert_id;
    GtkWidget *row_cert_password;
    GtkWidget *entry_cert_type;
    GtkWidget *entry_cert_path;
    GtkWidget *entry_cert_id;
    GtkWidget *entry_cert_password;

    GtkWidget *entry_if_name;
    GtkWidget *spin_mtu;

    GtkWidget *entry_dns_servers;
    GtkWidget *entry_ignore_dns_servers;
    GtkWidget *entry_search_domains;
    GtkWidget *entry_ignore_search_domains;
    GtkWidget *check_set_routing_domains;
    GtkWidget *spin_dns_priority;
    GtkWidget *check_disable_ipv6;

    GtkWidget *check_default_route;
    GtkWidget *check_no_routing;
    GtkWidget *entry_add_routes;
    GtkWidget *entry_ignore_routes;
    GtkWidget *check_allow_forwarding;

    GtkWidget *entry_ca_cert;
    GtkWidget *check_ignore_server_cert;

    GtkWidget *check_no_keepalive;
    GtkWidget *check_port_knock;
    GtkWidget *check_ike_persist;
    GtkWidget *spin_ike_lifetime;
    GtkWidget *spin_ip_lease_time;
} SnxEditor;

typedef struct {
    GObjectClass parent_class;
} SnxEditorClass;

#define SNX_EDITOR(obj) (G_TYPE_CHECK_INSTANCE_CAST((obj), SNX_TYPE_EDITOR, SnxEditor))

static void snx_editor_iface_init(NMVpnEditorInterface *iface);

G_DEFINE_TYPE_WITH_CODE(SnxEditor,
                        snx_editor,
                        G_TYPE_OBJECT,
                        G_IMPLEMENT_INTERFACE(NM_TYPE_VPN_EDITOR, snx_editor_iface_init))

static const char *const tunnel_type_options[] = {"ipsec", "ssl", NULL};
static const char *const transport_type_options[] = {"auto", "kernel", "udp", "tcpt", NULL};
static const char *const login_type_placeholder = "Use Query… to load login types";

/* ---- small value helpers ---- */

static char *
csv_join(GPtrArray *array)
{
    GString *result;

    if (array == NULL || array->len == 0)
        return g_strdup("");

    result = g_string_new(NULL);
    for (guint i = 0; i < array->len; i++) {
        if (i > 0)
            g_string_append(result, ", ");
        g_string_append(result, (const char *) g_ptr_array_index(array, i));
    }

    return g_string_free(result, FALSE);
}

static const char *
dropdown_get_value(GtkWidget *dropdown, const char *const *options)
{
    guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(dropdown));

    return options[selected];
}

static void
dropdown_set_value(GtkWidget *dropdown, const char *const *options, const char *value)
{
    if (value != NULL && *value != '\0') {
        for (guint i = 0; options[i] != NULL; i++) {
            if (g_ascii_strcasecmp(options[i], value) == 0) {
                gtk_drop_down_set_selected(GTK_DROP_DOWN(dropdown), i);
                return;
            }
        }
    }

    gtk_drop_down_set_selected(GTK_DROP_DOWN(dropdown), 0);
}

static void
set_data(NMSettingVpn *s_vpn, const char *key, const char *value)
{
    if (value != NULL && *value != '\0')
        nm_setting_vpn_add_data_item(s_vpn, key, value);
    else
        nm_setting_vpn_remove_data_item(s_vpn, key);
}

static void
set_data_bool(NMSettingVpn *s_vpn, const char *key, gboolean value)
{
    nm_setting_vpn_add_data_item(s_vpn, key, value ? "true" : "false");
}

static void
set_data_uint(NMSettingVpn *s_vpn, const char *key, guint value)
{
    g_autofree char *text = g_strdup_printf("%u", value);

    nm_setting_vpn_add_data_item(s_vpn, key, text);
}

static void
set_data_int(NMSettingVpn *s_vpn, const char *key, int value)
{
    g_autofree char *text = g_strdup_printf("%d", value);

    nm_setting_vpn_add_data_item(s_vpn, key, text);
}

/* Saves a password field backed by the standard "Store for this user /
 * for all users / ask every time / not required" menu (see
 * setup_password_row()). If the field is empty but the user did not
 * choose "ask every time" or "not required", the existing stored secret
 * (if any) is left untouched instead of being wiped — the field is always
 * blank when the editor loads an existing connection, regardless of
 * whether a secret is already stored, so an empty field here does not
 * mean "the user wants to clear it". */
static void
set_password_secret(NMSettingVpn *s_vpn, const char *key, const char *value, GtkWidget *password_entry)
{
    NMSettingSecretFlags flags = nma_utils_menu_to_secret_flags(password_entry);
    g_autofree char *flags_key = g_strdup_printf("%s-flags", key);
    g_autofree char *flags_text = g_strdup_printf("%d", (int) flags);

    if (value != NULL && *value != '\0')
        nm_setting_vpn_add_secret(s_vpn, key, value);
    else if (flags == NM_SETTING_SECRET_FLAG_NOT_SAVED || flags == NM_SETTING_SECRET_FLAG_NOT_REQUIRED)
        nm_setting_vpn_remove_secret(s_vpn, key);

    nm_setting_vpn_add_data_item(s_vpn, flags_key, flags_text);
}

/* Forces a secret to "not required" and clears any stored value, used when
 * a whole optional sub-form (e.g. the certificate fields) is toggled off. */
static void
clear_password_secret(NMSettingVpn *s_vpn, const char *key)
{
    g_autofree char *flags_key = g_strdup_printf("%s-flags", key);
    g_autofree char *flags_text = g_strdup_printf("%d", (int) NM_SETTING_SECRET_FLAG_NOT_REQUIRED);

    nm_setting_vpn_remove_secret(s_vpn, key);
    nm_setting_vpn_add_data_item(s_vpn, flags_key, flags_text);
}

static NMSettingSecretFlags
get_stored_secret_flags(NMSettingVpn *s_vpn, const char *key)
{
    g_autofree char *flags_key = g_strdup_printf("%s-flags", key);
    const char *value = nm_setting_vpn_get_data_item(s_vpn, flags_key);

    /* No stored preference yet (new connection, or one created before this
     * flag existed): default to the same choice the storage menu itself
     * defaults to for a freshly typed password, "store for this user". */
    if (value == NULL)
        return NM_SETTING_SECRET_FLAG_AGENT_OWNED;

    return (NMSettingSecretFlags) g_ascii_strtoll(value, NULL, 10);
}

/* ---- change notification ---- */

static void
emit_changed(SnxEditor *self)
{
    g_signal_emit_by_name(self, "changed");
}

static void
connect_changed(SnxEditor *self, GtkWidget *widget)
{
    if (GTK_IS_DROP_DOWN(widget))
        g_signal_connect_swapped(widget, "notify::selected", G_CALLBACK(emit_changed), self);
    else if (GTK_IS_CHECK_BUTTON(widget))
        g_signal_connect_swapped(widget, "toggled", G_CALLBACK(emit_changed), self);
    else if (GTK_IS_SPIN_BUTTON(widget))
        g_signal_connect_swapped(widget, "value-changed", G_CALLBACK(emit_changed), self);
    else if (GTK_IS_EDITABLE(widget))
        g_signal_connect_swapped(widget, "changed", G_CALLBACK(emit_changed), self);
}

/* ---- widget construction helpers ---- */

static GtkWidget *
grid_add_row(GtkGrid *grid, int row, const char *label_text, GtkWidget *widget)
{
    GtkWidget *label = gtk_label_new(label_text);

    gtk_label_set_xalign(GTK_LABEL(label), 1.0);
    gtk_label_set_width_chars(GTK_LABEL(label), 20);
    gtk_widget_set_hexpand(widget, TRUE);
    gtk_grid_attach(grid, label, 0, row, 1, 1);
    gtk_grid_attach(grid, widget, 1, row, 1, 1);

    return label;
}

static GtkWidget *
new_entry_row_full(GtkGrid *grid, int row, const char *label_text, GtkWidget **out_label, GtkWidget **out_row_widget)
{
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *label = grid_add_row(grid, row, label_text, entry);

    if (out_label != NULL)
        *out_label = label;
    if (out_row_widget != NULL)
        *out_row_widget = entry;

    return entry;
}

static GtkWidget *
new_entry_row(GtkGrid *grid, int row, const char *label_text)
{
    return new_entry_row_full(grid, row, label_text, NULL, NULL);
}

/* Plain GtkEntry with visibility off, not GtkPasswordEntry: libnma's
 * nma_utils_setup_password_storage() casts the widget to GTK_ENTRY() and
 * manipulates it with GtkEntry-only APIs (secondary icon, can-focus toggling
 * for the "ask every time"/"not required" modes). GtkPasswordEntry does not
 * inherit GtkEntry in GTK4, so pairing it with that call left the field
 * silently non-focusable whenever those modes were the stored default. */
static GtkWidget *
new_password_row_full(GtkGrid *grid, int row, const char *label_text, GtkWidget **out_label, GtkWidget **out_row_widget)
{
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *label;

    gtk_entry_set_visibility(GTK_ENTRY(entry), FALSE);
    label = grid_add_row(grid, row, label_text, entry);
    if (out_label != NULL)
        *out_label = label;
    if (out_row_widget != NULL)
        *out_row_widget = entry;

    return entry;
}

static GtkWidget *
new_password_row(GtkGrid *grid, int row, const char *label_text)
{
    return new_password_row_full(grid, row, label_text, NULL, NULL);
}

static void
on_file_chosen(GObject *source, GAsyncResult *result, gpointer user_data)
{
    GtkWidget *entry = user_data;
    g_autoptr(GFile) file = gtk_file_dialog_open_finish(GTK_FILE_DIALOG(source), result, NULL);

    if (file != NULL) {
        g_autofree char *path = g_file_get_path(file);

        if (path != NULL)
            gtk_editable_set_text(GTK_EDITABLE(entry), path);
    }

    g_object_unref(source);
}

static void
on_browse_clicked(GtkButton *button, gpointer user_data)
{
    GtkWidget *entry = GTK_WIDGET(user_data);
    GtkRoot *root = gtk_widget_get_root(GTK_WIDGET(button));
    GtkFileDialog *dialog = gtk_file_dialog_new();

    gtk_file_dialog_open(dialog, GTK_IS_WINDOW(root) ? GTK_WINDOW(root) : NULL, NULL, on_file_chosen, entry);
}

static GtkWidget *
new_file_entry_row_full(GtkGrid *grid, int row, const char *label_text, GtkWidget **out_label, GtkWidget **out_row_widget)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *entry = gtk_entry_new();
    GtkWidget *button = gtk_button_new_with_label("Browse…");
    GtkWidget *label;

    gtk_widget_set_hexpand(entry, TRUE);
    gtk_box_append(GTK_BOX(box), entry);
    gtk_box_append(GTK_BOX(box), button);
    g_signal_connect(button, "clicked", G_CALLBACK(on_browse_clicked), entry);

    label = grid_add_row(grid, row, label_text, box);
    if (out_label != NULL)
        *out_label = label;
    if (out_row_widget != NULL)
        *out_row_widget = box;

    return entry;
}

static GtkWidget *
new_file_entry_row(GtkGrid *grid, int row, const char *label_text)
{
    return new_file_entry_row_full(grid, row, label_text, NULL, NULL);
}

/* ---- gateway login-type discovery ---- */

typedef struct {
    char *server_name;
    gboolean ignore_server_cert;
} QueryLoginTypesTaskData;

static void
query_login_types_task_data_free(QueryLoginTypesTaskData *data)
{
    g_free(data->server_name);
    g_free(data);
}

static void
query_login_types_thread(GTask *task, gpointer source_object, gpointer task_data, GCancellable *cancellable)
{
    QueryLoginTypesTaskData *data = task_data;
    SnxCccOptions options = {0};
    SnxGatewayInfo *info = NULL;
    GError *error = NULL;

    (void) source_object;
    (void) cancellable;

    options.server_name = data->server_name;
    options.ignore_server_cert = data->ignore_server_cert;

    if (!snx_ccc_get_gateway_info(&options, &info, &error)) {
        g_task_return_error(task, error);
        return;
    }

    g_task_return_pointer(task, info, (GDestroyNotify) snx_gateway_info_free);
}

static void
close_login_type_popover(SnxEditor *self)
{
    if (self->login_type_popover != NULL) {
        gtk_widget_unparent(self->login_type_popover);
        self->login_type_popover = NULL;
    }
}

static void
show_login_type_message_popover(SnxEditor *self, GtkWidget *parent, const char *message)
{
    GtkWidget *label = gtk_label_new(message);
    GtkWidget *popover;

    close_login_type_popover(self);

    gtk_label_set_wrap(GTK_LABEL(label), TRUE);
    gtk_widget_set_margin_start(label, 8);
    gtk_widget_set_margin_end(label, 8);
    gtk_widget_set_margin_top(label, 8);
    gtk_widget_set_margin_bottom(label, 8);

    popover = gtk_popover_new();
    gtk_popover_set_child(GTK_POPOVER(popover), label);
    gtk_widget_set_parent(popover, parent);

    self->login_type_popover = popover;
    gtk_popover_popup(GTK_POPOVER(popover));
}

static const char *
login_type_get_selected_id(SnxEditor *self)
{
    guint selected = gtk_drop_down_get_selected(GTK_DROP_DOWN(self->dropdown_login_type));

    if (selected == GTK_INVALID_LIST_POSITION || self->login_type_ids == NULL ||
        selected >= self->login_type_ids->len)
        return NULL;

    return g_ptr_array_index(self->login_type_ids, selected);
}

/* Populates the Login type combo from (ids[i], labels[i]) pairs, copying
 * both arrays; ids/labels are only read, never taken over. Re-selects
 * preferred_id if it is still present, otherwise selects the first entry.
 * A placeholder row keeps a new profile from showing GTK's generic "None". */
static void
set_login_type_options(SnxEditor *self, GPtrArray *ids, GPtrArray *labels, const char *preferred_id)
{
    g_autoptr(GtkStringList) model = gtk_string_list_new(NULL);
    guint select_index = 0;
    guint i;

    g_clear_pointer(&self->login_type_ids, g_ptr_array_unref);
    self->login_type_ids = g_ptr_array_new_with_free_func(g_free);

    if (ids->len == 0) {
        gtk_string_list_append(model, login_type_placeholder);
        g_ptr_array_add(self->login_type_ids, g_strdup(""));
        gtk_drop_down_set_model(GTK_DROP_DOWN(self->dropdown_login_type), G_LIST_MODEL(model));
        gtk_drop_down_set_selected(GTK_DROP_DOWN(self->dropdown_login_type), 0);
        return;
    }

    for (i = 0; i < ids->len; i++) {
        const char *id = g_ptr_array_index(ids, i);

        gtk_string_list_append(model, g_ptr_array_index(labels, i));
        g_ptr_array_add(self->login_type_ids, g_strdup(id));
        if (preferred_id != NULL && g_strcmp0(id, preferred_id) == 0)
            select_index = i;
    }

    gtk_drop_down_set_model(GTK_DROP_DOWN(self->dropdown_login_type), G_LIST_MODEL(model));
    gtk_drop_down_set_selected(GTK_DROP_DOWN(self->dropdown_login_type), select_index);
}

static void
on_query_login_type_done(GObject *source, GAsyncResult *result, gpointer user_data)
{
    SnxEditor *self = SNX_EDITOR(source);
    GtkWidget *button = GTK_WIDGET(user_data);
    g_autoptr(GError) error = NULL;
    SnxGatewayInfo *info = g_task_propagate_pointer(G_TASK(result), &error);
    g_autoptr(GPtrArray) ids = NULL;
    g_autoptr(GPtrArray) labels = NULL;
    const char *previous_id;
    guint i;

    gtk_widget_set_sensitive(button, TRUE);

    if (info == NULL) {
        show_login_type_message_popover(self, button, error != NULL ? error->message : "Unknown error");
        return;
    }

    if (info->login_options->len == 0) {
        show_login_type_message_popover(self, button, "The gateway did not advertise any login methods.");
        snx_gateway_info_free(info);
        return;
    }

    previous_id = login_type_get_selected_id(self);
    ids = g_ptr_array_new();
    labels = g_ptr_array_new();

    for (i = 0; i < info->login_options->len; i++) {
        SnxLoginOption *option = g_ptr_array_index(info->login_options, i);
        char *label = g_strdup_printf("%s (%s)", option->display_name, option->id);

        g_ptr_array_add(ids, option->id);
        g_ptr_array_add(labels, label);
    }

    set_login_type_options(self, ids, labels, previous_id);

    for (i = 0; i < labels->len; i++)
        g_free(g_ptr_array_index(labels, i));

    snx_gateway_info_free(info);
}

static void
on_query_login_type_clicked(GtkButton *button, gpointer user_data)
{
    SnxEditor *self = user_data;
    const char *server = gtk_editable_get_text(GTK_EDITABLE(self->entry_server));
    gboolean ignore_cert = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_ignore_server_cert));
    QueryLoginTypesTaskData *data;
    GTask *task;

    if (server == NULL || *server == '\0') {
        show_login_type_message_popover(self, GTK_WIDGET(button), "Enter the gateway address first.");
        return;
    }

    gtk_widget_set_sensitive(GTK_WIDGET(button), FALSE);

    data = g_new0(QueryLoginTypesTaskData, 1);
    data->server_name = g_strdup(server);
    data->ignore_server_cert = ignore_cert;

    task = g_task_new(self, NULL, on_query_login_type_done, button);
    g_task_set_task_data(task, data, (GDestroyNotify) query_login_types_task_data_free);
    g_task_run_in_thread(task, query_login_types_thread);
    g_object_unref(task);
}

static GtkWidget *
new_server_row(GtkGrid *grid, int row, SnxEditor *self)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 6);
    GtkWidget *entry = gtk_entry_new();

    self->button_query_login_type = gtk_button_new_with_label("Query…");

    gtk_widget_set_hexpand(entry, TRUE);
    gtk_widget_set_tooltip_text(self->button_query_login_type,
                                "Fetch the gateway's real login methods (read-only, no credentials sent) "
                                "and choose the login type");
    gtk_box_append(GTK_BOX(box), entry);
    gtk_box_append(GTK_BOX(box), self->button_query_login_type);
    g_signal_connect(self->button_query_login_type, "clicked", G_CALLBACK(on_query_login_type_clicked), self);

    grid_add_row(grid, row, "Gateway address", box);
    return entry;
}

static GtkWidget *
new_check_row(GtkGrid *grid, int row, const char *label_text)
{
    GtkWidget *check = gtk_check_button_new_with_label(label_text);

    gtk_grid_attach(grid, check, 0, row, 2, 1);
    return check;
}

static GtkWidget *
new_spin_row(GtkGrid *grid, int row, const char *label_text, double min, double max, double step)
{
    GtkWidget *spin = gtk_spin_button_new_with_range(min, max, step);

    grid_add_row(grid, row, label_text, spin);
    return spin;
}

static GtkWidget *
new_dropdown_row(GtkGrid *grid, int row, const char *label_text, const char *const *options)
{
    GtkWidget *dropdown = gtk_drop_down_new_from_strings(options);

    grid_add_row(grid, row, label_text, dropdown);
    return dropdown;
}

static GtkGrid *
new_grid(void)
{
    GtkWidget *grid = gtk_grid_new();

    gtk_grid_set_row_spacing(GTK_GRID(grid), 8);
    gtk_grid_set_column_spacing(GTK_GRID(grid), 12);
    gtk_widget_set_margin_start(grid, 6);

    return GTK_GRID(grid);
}

static GtkGrid *
new_section(GtkBox *container, const char *title)
{
    GtkWidget *label = gtk_label_new(NULL);
    g_autofree char *markup = g_markup_printf_escaped("<b>%s</b>", title);
    GtkGrid *grid = new_grid();

    gtk_label_set_markup(GTK_LABEL(label), markup);
    gtk_label_set_xalign(GTK_LABEL(label), 0.0);
    gtk_widget_set_margin_top(label, 6);
    gtk_box_append(container, label);
    gtk_box_append(container, GTK_WIDGET(grid));

    return grid;
}

static GtkGrid *
new_tab_page(GtkNotebook *notebook, const char *title)
{
    GtkWidget *scrolled = gtk_scrolled_window_new();
    GtkGrid *grid = new_grid();

    gtk_scrolled_window_set_policy(GTK_SCROLLED_WINDOW(scrolled), GTK_POLICY_NEVER, GTK_POLICY_AUTOMATIC);
    gtk_widget_set_margin_start(GTK_WIDGET(grid), 12);
    gtk_widget_set_margin_end(GTK_WIDGET(grid), 12);
    gtk_widget_set_margin_top(GTK_WIDGET(grid), 12);
    gtk_widget_set_margin_bottom(GTK_WIDGET(grid), 12);
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(scrolled), GTK_WIDGET(grid));
    gtk_notebook_append_page(notebook, scrolled, gtk_label_new(title));

    return grid;
}

/* ---- "use certificate" visibility ---- */

static void
set_certificate_fields_visible(SnxEditor *self, gboolean visible)
{
    GtkWidget *widgets[] = {
        self->label_cert_type,
        self->row_cert_type,
        self->label_cert_path,
        self->row_cert_path,
        self->label_cert_id,
        self->row_cert_id,
        self->label_cert_password,
        self->row_cert_password,
    };

    for (guint i = 0; i < G_N_ELEMENTS(widgets); i++) {
        if (widgets[i] != NULL)
            gtk_widget_set_visible(widgets[i], visible);
    }
}

static void
on_use_certificate_toggled(GtkCheckButton *button, gpointer user_data)
{
    SnxEditor *self = user_data;

    set_certificate_fields_visible(self, gtk_check_button_get_active(button));
}

/* ---- advanced settings dialog ---- */

static void
snapshot_clear(SnxAdvancedSnapshot *snap)
{
    g_clear_pointer(&snap->if_name, g_free);
    g_clear_pointer(&snap->dns_servers, g_free);
    g_clear_pointer(&snap->ignore_dns_servers, g_free);
    g_clear_pointer(&snap->search_domains, g_free);
    g_clear_pointer(&snap->ignore_search_domains, g_free);
    g_clear_pointer(&snap->add_routes, g_free);
    g_clear_pointer(&snap->ignore_routes, g_free);
    g_clear_pointer(&snap->ca_cert, g_free);
    memset(snap, 0, sizeof(*snap));
}

static void
snapshot_take(SnxEditor *self, SnxAdvancedSnapshot *snap)
{
    snapshot_clear(snap);

    snap->if_name = g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_if_name)));
    snap->mtu = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_mtu));

    snap->dns_servers = g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_dns_servers)));
    snap->ignore_dns_servers = g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_ignore_dns_servers)));
    snap->search_domains = g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_search_domains)));
    snap->ignore_search_domains =
        g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_ignore_search_domains)));
    snap->set_routing_domains = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_set_routing_domains));
    snap->dns_priority = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_dns_priority));
    snap->disable_ipv6 = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_disable_ipv6));

    snap->default_route = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_default_route));
    snap->no_routing = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_no_routing));
    snap->add_routes = g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_add_routes)));
    snap->ignore_routes = g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_ignore_routes)));
    snap->allow_forwarding = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_allow_forwarding));

    snap->ca_cert = g_strdup(gtk_editable_get_text(GTK_EDITABLE(self->entry_ca_cert)));
    snap->ignore_server_cert = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_ignore_server_cert));

    snap->no_keepalive = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_no_keepalive));
    snap->port_knock = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_port_knock));
    snap->ike_persist = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_ike_persist));
    snap->ike_lifetime = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_ike_lifetime));
    snap->ip_lease_time = gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_ip_lease_time));
}

static void
snapshot_restore(SnxEditor *self, const SnxAdvancedSnapshot *snap)
{
    gtk_editable_set_text(GTK_EDITABLE(self->entry_if_name), snap->if_name);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_mtu), snap->mtu);

    gtk_editable_set_text(GTK_EDITABLE(self->entry_dns_servers), snap->dns_servers);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_ignore_dns_servers), snap->ignore_dns_servers);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_search_domains), snap->search_domains);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_ignore_search_domains), snap->ignore_search_domains);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_set_routing_domains), snap->set_routing_domains);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_dns_priority), snap->dns_priority);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_disable_ipv6), snap->disable_ipv6);

    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_default_route), snap->default_route);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_no_routing), snap->no_routing);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_add_routes), snap->add_routes);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_ignore_routes), snap->ignore_routes);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_allow_forwarding), snap->allow_forwarding);

    gtk_editable_set_text(GTK_EDITABLE(self->entry_ca_cert), snap->ca_cert);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_ignore_server_cert), snap->ignore_server_cert);

    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_no_keepalive), snap->no_keepalive);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_port_knock), snap->port_knock);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_ike_persist), snap->ike_persist);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_ike_lifetime), snap->ike_lifetime);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_ip_lease_time), snap->ip_lease_time);
}

static void
on_advanced_cancel_clicked(GtkButton *button, gpointer user_data)
{
    SnxEditor *self = user_data;

    (void) button;
    snapshot_restore(self, &self->advanced_snapshot);
    snapshot_clear(&self->advanced_snapshot);
    gtk_widget_set_visible(self->advanced_dialog, FALSE);
}

static void
on_advanced_apply_clicked(GtkButton *button, gpointer user_data)
{
    SnxEditor *self = user_data;

    (void) button;
    snapshot_clear(&self->advanced_snapshot);
    gtk_widget_set_visible(self->advanced_dialog, FALSE);
    emit_changed(self);
}

static void
on_advanced_clicked(GtkButton *button, gpointer user_data)
{
    SnxEditor *self = user_data;
    GtkRoot *root = gtk_widget_get_root(GTK_WIDGET(button));

    snapshot_take(self, &self->advanced_snapshot);

    if (GTK_IS_WINDOW(root))
        gtk_window_set_transient_for(GTK_WINDOW(self->advanced_dialog), GTK_WINDOW(root));

    gtk_window_present(GTK_WINDOW(self->advanced_dialog));
}

static void
build_advanced_dialog(SnxEditor *self)
{
    GtkWidget *dialog = gtk_window_new();
    GtkWidget *header = gtk_header_bar_new();
    GtkWidget *title_label = gtk_label_new(NULL);
    GtkWidget *cancel_button = gtk_button_new_with_label("Cancel");
    GtkWidget *apply_button = gtk_button_new_with_label("Apply");
    GtkWidget *notebook = gtk_notebook_new();
    GtkGrid *grid;
    int row;

    gtk_window_set_title(GTK_WINDOW(dialog), "Advanced Settings");
    gtk_window_set_default_size(GTK_WINDOW(dialog), 480, 480);
    gtk_window_set_modal(GTK_WINDOW(dialog), TRUE);
    gtk_window_set_hide_on_close(GTK_WINDOW(dialog), TRUE);

    gtk_label_set_markup(GTK_LABEL(title_label), "<b>Advanced Settings</b>");
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), title_label);
    gtk_header_bar_set_show_title_buttons(GTK_HEADER_BAR(header), FALSE);
    gtk_header_bar_pack_start(GTK_HEADER_BAR(header), cancel_button);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), apply_button);
    gtk_widget_add_css_class(apply_button, "suggested-action");
    gtk_window_set_titlebar(GTK_WINDOW(dialog), header);
    g_signal_connect(cancel_button, "clicked", G_CALLBACK(on_advanced_cancel_clicked), self);
    g_signal_connect(apply_button, "clicked", G_CALLBACK(on_advanced_apply_clicked), self);

    gtk_window_set_child(GTK_WINDOW(dialog), notebook);

    grid = new_tab_page(GTK_NOTEBOOK(notebook), "General");
    row = 0;
    self->entry_if_name = new_entry_row(grid, row++, "Interface name");
    self->spin_mtu = new_spin_row(grid, row++, "MTU", 576, 9000, 1);

    grid = new_tab_page(GTK_NOTEBOOK(notebook), "DNS");
    row = 0;
    self->entry_dns_servers = new_entry_row(grid, row++, "Additional DNS servers");
    self->entry_ignore_dns_servers = new_entry_row(grid, row++, "Ignored DNS servers");
    self->entry_search_domains = new_entry_row(grid, row++, "Search domains");
    self->entry_ignore_search_domains = new_entry_row(grid, row++, "Ignored search domains");
    self->check_set_routing_domains = new_check_row(grid, row++, "Use routing domains for split DNS");
    self->spin_dns_priority = new_spin_row(grid, row++, "DNS priority", -1000, 1000, 1);
    self->check_disable_ipv6 = new_check_row(grid, row++, "Disable IPv6 while connected");

    grid = new_tab_page(GTK_NOTEBOOK(notebook), "Routing");
    row = 0;
    self->check_default_route = new_check_row(grid, row++, "Use as default route");
    self->check_no_routing = new_check_row(grid, row++, "Ignore routes received from the gateway");
    self->entry_add_routes = new_entry_row(grid, row++, "Additional routes");
    self->entry_ignore_routes = new_entry_row(grid, row++, "Ignored routes");
    self->check_allow_forwarding = new_check_row(grid, row++, "Allow forwarding");

    grid = new_tab_page(GTK_NOTEBOOK(notebook), "Certificate");
    row = 0;
    self->entry_ca_cert = new_file_entry_row(grid, row++, "CA certificate path");
    self->check_ignore_server_cert = new_check_row(grid, row++, "Ignore server certificate (insecure)");

    grid = new_tab_page(GTK_NOTEBOOK(notebook), "Session");
    row = 0;
    self->check_no_keepalive = new_check_row(grid, row++, "Disable IPsec keepalive");
    self->check_port_knock = new_check_row(grid, row++, "NAT-T port knock");
    self->check_ike_persist = new_check_row(grid, row++, "Persist IKE session");
    self->spin_ike_lifetime = new_spin_row(grid, row++, "IKE lifetime (seconds)", 0, 604800, 60);
    self->spin_ip_lease_time = new_spin_row(grid, row++, "IP lease time (seconds)", 0, 604800, 60);

    self->advanced_dialog = dialog;
    g_object_ref_sink(self->advanced_dialog);
}

/* ---- main widget ---- */

static void
build_ui(SnxEditor *self)
{
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    GtkWidget *advanced_row = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    GtkWidget *advanced_button = gtk_button_new_with_label("Advanced…");
    GtkGrid *grid;
    int row;

    gtk_widget_set_margin_start(box, 6);
    gtk_widget_set_margin_end(box, 6);
    gtk_widget_set_margin_top(box, 6);
    gtk_widget_set_margin_bottom(box, 6);

    grid = new_section(GTK_BOX(box), "General");
    row = 0;
    self->entry_server = new_server_row(grid, row++, self);
    self->dropdown_login_type = gtk_drop_down_new(NULL, NULL);
    grid_add_row(grid, row++, "Login type", self->dropdown_login_type);
    gtk_widget_set_tooltip_text(self->dropdown_login_type,
                                "Use the \"Query…\" button next to Gateway address to load the real "
                                "login methods from the server.");
    self->dropdown_tunnel_type = new_dropdown_row(grid, row++, "Tunnel type", tunnel_type_options);
    self->dropdown_transport_type = new_dropdown_row(grid, row++, "IPsec transport", transport_type_options);

    grid = new_section(GTK_BOX(box), "Authentication");
    row = 0;
    self->entry_username = new_entry_row(grid, row++, "User name");
    self->entry_password = new_password_row(grid, row++, "Password");
    self->check_use_certificate = new_check_row(grid, row++, "Use a client certificate");
    g_signal_connect(self->check_use_certificate,
                     "toggled",
                     G_CALLBACK(on_use_certificate_toggled),
                     self);

    self->entry_cert_type =
        new_entry_row_full(grid, row++, "Certificate type", &self->label_cert_type, &self->row_cert_type);
    self->entry_cert_path =
        new_file_entry_row_full(grid, row++, "Certificate path", &self->label_cert_path, &self->row_cert_path);
    self->entry_cert_id =
        new_entry_row_full(grid, row++, "Certificate/token ID", &self->label_cert_id, &self->row_cert_id);
    self->entry_cert_password = new_password_row_full(grid,
                                                      row++,
                                                      "Certificate password",
                                                      &self->label_cert_password,
                                                      &self->row_cert_password);
    set_certificate_fields_visible(self, FALSE);

    build_advanced_dialog(self);

    gtk_widget_set_halign(advanced_row, GTK_ALIGN_END);
    gtk_widget_set_margin_top(advanced_row, 8);
    g_signal_connect(advanced_button, "clicked", G_CALLBACK(on_advanced_clicked), self);
    gtk_box_append(GTK_BOX(advanced_row), advanced_button);
    gtk_box_append(GTK_BOX(box), advanced_row);

    self->widget = box;
    g_object_ref_sink(self->widget);

    GtkWidget *widgets[] = {
        self->entry_server,
        self->dropdown_tunnel_type,
        self->dropdown_transport_type,
        self->dropdown_login_type,
        self->check_use_certificate,
        self->entry_username,
        self->entry_password,
        self->entry_cert_type,
        self->entry_cert_path,
        self->entry_cert_id,
        self->entry_cert_password,
        self->entry_if_name,
        self->spin_mtu,
        self->entry_dns_servers,
        self->entry_ignore_dns_servers,
        self->entry_search_domains,
        self->entry_ignore_search_domains,
        self->check_set_routing_domains,
        self->spin_dns_priority,
        self->check_disable_ipv6,
        self->check_default_route,
        self->check_no_routing,
        self->entry_add_routes,
        self->entry_ignore_routes,
        self->check_allow_forwarding,
        self->entry_ca_cert,
        self->check_ignore_server_cert,
        self->check_no_keepalive,
        self->check_port_knock,
        self->check_ike_persist,
        self->spin_ike_lifetime,
        self->spin_ip_lease_time,
    };

    for (guint i = 0; i < G_N_ELEMENTS(widgets); i++)
        connect_changed(self, widgets[i]);
}

/* ---- NMVpnEditor interface ---- */

static GObject *
snx_editor_get_widget(NMVpnEditor *editor)
{
    SnxEditor *self = SNX_EDITOR(editor);

    return G_OBJECT(self->widget);
}

static gboolean
snx_editor_update_connection(NMVpnEditor *editor, NMConnection *connection, GError **error)
{
    SnxEditor *self = SNX_EDITOR(editor);
    NMSettingVpn *s_vpn;
    const char *server = gtk_editable_get_text(GTK_EDITABLE(self->entry_server));
    const char *login_type = login_type_get_selected_id(self);
    const char *username;
    gboolean use_certificate = gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_use_certificate));

    if (server == NULL || *server == '\0') {
        g_set_error(error, NM_VPN_PLUGIN_ERROR, NM_VPN_PLUGIN_ERROR_INVALID_CONNECTION, "server-name is required");
        return FALSE;
    }

    /* login-type is intentionally not required while saving: a new profile may
     * not have run Query yet. It is still required by snx_config_validate_for_connect()
     * before actually connecting. */

    s_vpn = nm_connection_get_setting_vpn(connection);
    if (s_vpn == NULL) {
        s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
        nm_connection_add_setting(connection, NM_SETTING(s_vpn));
    }

    g_object_set(s_vpn, NM_SETTING_VPN_SERVICE_TYPE, SNX_DBUS_SERVICE_NAME, NULL);

    username = gtk_editable_get_text(GTK_EDITABLE(self->entry_username));
    g_object_set(s_vpn,
                NM_SETTING_VPN_USER_NAME,
                (username != NULL && *username != '\0') ? username : NULL,
                NULL);

    set_data(s_vpn, "server-name", server);
    set_data(s_vpn, "login-type", login_type);
    set_data(s_vpn, "tunnel-type", dropdown_get_value(self->dropdown_tunnel_type, tunnel_type_options));
    set_data(s_vpn, "transport-type", dropdown_get_value(self->dropdown_transport_type, transport_type_options));
    set_data(s_vpn, "if-name", gtk_editable_get_text(GTK_EDITABLE(self->entry_if_name)));
    set_data_uint(s_vpn, "mtu", (guint) gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_mtu)));

    set_data(s_vpn, "cert-type", use_certificate ? gtk_editable_get_text(GTK_EDITABLE(self->entry_cert_type)) : "");
    set_data(s_vpn, "cert-path", use_certificate ? gtk_editable_get_text(GTK_EDITABLE(self->entry_cert_path)) : "");
    set_data(s_vpn, "cert-id", use_certificate ? gtk_editable_get_text(GTK_EDITABLE(self->entry_cert_id)) : "");
    set_data(s_vpn, "ca-cert", gtk_editable_get_text(GTK_EDITABLE(self->entry_ca_cert)));
    set_data_bool(s_vpn,
                 "ignore-server-cert",
                 gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_ignore_server_cert)));

    set_data_bool(s_vpn, "default-route", gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_default_route)));
    set_data_bool(s_vpn, "no-routing", gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_no_routing)));
    set_data(s_vpn, "add-routes", gtk_editable_get_text(GTK_EDITABLE(self->entry_add_routes)));
    set_data(s_vpn, "ignore-routes", gtk_editable_get_text(GTK_EDITABLE(self->entry_ignore_routes)));
    set_data_bool(s_vpn,
                 "allow-forwarding",
                 gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_allow_forwarding)));

    set_data(s_vpn, "dns-servers", gtk_editable_get_text(GTK_EDITABLE(self->entry_dns_servers)));
    set_data(s_vpn, "ignore-dns-servers", gtk_editable_get_text(GTK_EDITABLE(self->entry_ignore_dns_servers)));
    set_data(s_vpn, "search-domains", gtk_editable_get_text(GTK_EDITABLE(self->entry_search_domains)));
    set_data(s_vpn,
            "ignore-search-domains",
            gtk_editable_get_text(GTK_EDITABLE(self->entry_ignore_search_domains)));
    set_data_bool(s_vpn,
                 "set-routing-domains",
                 gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_set_routing_domains)));
    set_data_int(s_vpn, "dns-priority", gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_dns_priority)));
    set_data_bool(s_vpn, "disable-ipv6", gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_disable_ipv6)));

    set_data_bool(s_vpn, "no-keepalive", gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_no_keepalive)));
    set_data_bool(s_vpn, "port-knock", gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_port_knock)));
    set_data_bool(s_vpn, "ike-persist", gtk_check_button_get_active(GTK_CHECK_BUTTON(self->check_ike_persist)));
    set_data_uint(s_vpn,
                 "ike-lifetime",
                 (guint) gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_ike_lifetime)));
    set_data_uint(s_vpn,
                 "ip-lease-time",
                 (guint) gtk_spin_button_get_value_as_int(GTK_SPIN_BUTTON(self->spin_ip_lease_time)));

    set_password_secret(s_vpn, "password", gtk_editable_get_text(GTK_EDITABLE(self->entry_password)),
                        self->entry_password);
    if (use_certificate)
        set_password_secret(s_vpn, "cert-password", gtk_editable_get_text(GTK_EDITABLE(self->entry_cert_password)),
                            self->entry_cert_password);
    else
        clear_password_secret(s_vpn, "cert-password");

    return TRUE;
}

static void
snx_editor_iface_init(NMVpnEditorInterface *iface)
{
    iface->get_widget = snx_editor_get_widget;
    iface->update_connection = snx_editor_update_connection;
}

/* ---- GObject boilerplate ---- */

static void
snx_editor_finalize(GObject *object)
{
    SnxEditor *self = SNX_EDITOR(object);

    snapshot_clear(&self->advanced_snapshot);
    g_clear_pointer(&self->login_type_ids, g_ptr_array_unref);
    g_clear_object(&self->widget);
    g_clear_object(&self->advanced_dialog);

    G_OBJECT_CLASS(snx_editor_parent_class)->finalize(object);
}

static void
snx_editor_class_init(SnxEditorClass *klass)
{
    GObjectClass *object_class = G_OBJECT_CLASS(klass);

    object_class->finalize = snx_editor_finalize;
}

static void
snx_editor_init(SnxEditor *self)
{
    (void) self;
}

/* ---- public constructor ---- */

NMVpnEditor *
snx_editor_new(NMConnection *connection, GError **error)
{
    SnxEditor *self;
    SnxConfig config;
    NMSettingVpn *s_vpn;
    const char *username;
    const char *password;
    const char *cert_password;
    gboolean use_certificate;
    g_autofree char *dns_servers_csv = NULL;
    g_autofree char *ignore_dns_servers_csv = NULL;
    g_autofree char *search_domains_csv = NULL;
    g_autofree char *ignore_search_domains_csv = NULL;
    g_autofree char *add_routes_csv = NULL;
    g_autofree char *ignore_routes_csv = NULL;
    g_autofree char *ca_cert_csv = NULL;

    (void) error;

    self = SNX_EDITOR(g_object_new(snx_editor_get_type(), NULL));
    build_ui(self);

    snx_config_init(&config);
    snx_config_from_connection(&config, connection, NULL);

    gtk_editable_set_text(GTK_EDITABLE(self->entry_server), config.server_name != NULL ? config.server_name : "");
    dropdown_set_value(self->dropdown_tunnel_type, tunnel_type_options, config.tunnel_type);
    dropdown_set_value(self->dropdown_transport_type, transport_type_options, config.transport_type);

    {
        g_autoptr(GPtrArray) ids = g_ptr_array_new();
        g_autoptr(GPtrArray) labels = g_ptr_array_new();

        if (config.login_type != NULL && *config.login_type != '\0') {
            g_ptr_array_add(ids, config.login_type);
            g_ptr_array_add(labels, config.login_type);
        }
        set_login_type_options(self, ids, labels, config.login_type);
    }

    use_certificate = (config.cert_path != NULL && *config.cert_path != '\0') ||
                      (config.cert_type != NULL && *config.cert_type != '\0') ||
                      (config.cert_id != NULL && *config.cert_id != '\0');
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_use_certificate), use_certificate);
    set_certificate_fields_visible(self, use_certificate);

    gtk_editable_set_text(GTK_EDITABLE(self->entry_cert_type), config.cert_type != NULL ? config.cert_type : "");
    gtk_editable_set_text(GTK_EDITABLE(self->entry_cert_path), config.cert_path != NULL ? config.cert_path : "");
    gtk_editable_set_text(GTK_EDITABLE(self->entry_cert_id), config.cert_id != NULL ? config.cert_id : "");

    gtk_editable_set_text(GTK_EDITABLE(self->entry_if_name), config.if_name != NULL ? config.if_name : "");
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_mtu), config.mtu);

    ca_cert_csv = csv_join(config.ca_certs);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_ca_cert), ca_cert_csv);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_ignore_server_cert), config.ignore_server_cert);

    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_default_route), config.default_route);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_no_routing), config.no_routing);
    add_routes_csv = csv_join(config.add_routes);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_add_routes), add_routes_csv);
    ignore_routes_csv = csv_join(config.ignore_routes);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_ignore_routes), ignore_routes_csv);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_allow_forwarding), config.allow_forwarding);

    dns_servers_csv = csv_join(config.dns_servers);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_dns_servers), dns_servers_csv);
    ignore_dns_servers_csv = csv_join(config.ignore_dns_servers);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_ignore_dns_servers), ignore_dns_servers_csv);
    search_domains_csv = csv_join(config.search_domains);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_search_domains), search_domains_csv);
    ignore_search_domains_csv = csv_join(config.ignore_search_domains);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_ignore_search_domains), ignore_search_domains_csv);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_set_routing_domains), config.set_routing_domains);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_dns_priority), config.dns_priority);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_disable_ipv6), config.disable_ipv6);

    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_no_keepalive), config.no_keepalive);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_port_knock), config.port_knock);
    gtk_check_button_set_active(GTK_CHECK_BUTTON(self->check_ike_persist), config.ike_persist);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_ike_lifetime), config.ike_lifetime);
    gtk_spin_button_set_value(GTK_SPIN_BUTTON(self->spin_ip_lease_time), config.ip_lease_time);

    s_vpn = nm_connection_get_setting_vpn(connection);
    if (s_vpn == NULL) {
        s_vpn = NM_SETTING_VPN(nm_setting_vpn_new());
        nm_connection_add_setting(connection, NM_SETTING(s_vpn));
    }
    username = nm_setting_vpn_get_user_name(s_vpn);
    gtk_editable_set_text(GTK_EDITABLE(self->entry_username), username != NULL ? username : "");

    nma_utils_setup_password_storage(self->entry_password, get_stored_secret_flags(s_vpn, "password"),
                                     NM_SETTING(s_vpn), "password", TRUE, FALSE);
    nma_utils_setup_password_storage(self->entry_cert_password, get_stored_secret_flags(s_vpn, "cert-password"),
                                     NM_SETTING(s_vpn), "cert-password", TRUE, FALSE);

    /* Only populated when the caller (e.g. control-center) fetched secrets
     * before constructing the editor; a fresh/never-saved connection leaves
     * these NULL and the fields stay blank, which is expected. */
    password = nm_setting_vpn_get_secret(s_vpn, "password");
    gtk_editable_set_text(GTK_EDITABLE(self->entry_password), password != NULL ? password : "");
    cert_password = nm_setting_vpn_get_secret(s_vpn, "cert-password");
    gtk_editable_set_text(GTK_EDITABLE(self->entry_cert_password), cert_password != NULL ? cert_password : "");

    snx_config_clear(&config);

    return NM_VPN_EDITOR(self);
}
