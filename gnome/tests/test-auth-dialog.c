/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include <gio/gio.h>
#include <glib.h>

#define SNX_TEST_SERVICE "org.freedesktop.NetworkManager.snx"

static const char *stdin_no_password =
    "DATA_KEY=server-name\n"
    "DATA_VAL=vpn.example.com\n"
    "DATA_KEY=login-type\n"
    "DATA_VAL=vpn_password\n"
    "DONE\n";

static const char *stdin_with_password =
    "DATA_KEY=server-name\n"
    "DATA_VAL=vpn.example.com\n"
    "DATA_KEY=login-type\n"
    "DATA_VAL=vpn_password\n"
    "SECRET_KEY=password\n"
    "SECRET_VAL=hunter2\n"
    "DONE\n";

static GSubprocess *
spawn_auth_dialog(const char *path, const char *const *extra_args, GError **error)
{
    g_autoptr(GPtrArray) argv = g_ptr_array_new();

    g_ptr_array_add(argv, (gpointer) path);
    for (guint i = 0; extra_args != NULL && extra_args[i] != NULL; i++)
        g_ptr_array_add(argv, (gpointer) extra_args[i]);
    g_ptr_array_add(argv, NULL);

    return g_subprocess_newv((const char *const *) argv->pdata,
                             G_SUBPROCESS_FLAGS_STDIN_PIPE | G_SUBPROCESS_FLAGS_STDOUT_PIPE |
                                 G_SUBPROCESS_FLAGS_STDERR_PIPE,
                             error);
}

static void
run_auth_dialog(const char *path,
                const char *const *extra_args,
                const char *stdin_data,
                char **out_stdout,
                int *out_exit_status)
{
    g_autoptr(GSubprocess) proc = NULL;
    g_autoptr(GError) error = NULL;
    g_autofree char *stdout_buf = NULL;

    proc = spawn_auth_dialog(path, extra_args, &error);
    g_assert_no_error(error);
    g_assert_nonnull(proc);

    g_subprocess_communicate_utf8(proc, stdin_data, NULL, &stdout_buf, NULL, &error);
    g_assert_no_error(error);

    *out_stdout = g_steal_pointer(&stdout_buf);
    *out_exit_status = g_subprocess_get_exit_status(proc);
}

static void
test_rejects_wrong_service(gconstpointer user_data)
{
    const char *path = user_data;
    const char *args[] = {"-n", "Test", "-u", "11111111-1111-1111-1111-111111111111",
                          "-s", "org.freedesktop.NetworkManager.other", "--external-ui-mode", NULL};
    g_autofree char *stdout_buf = NULL;
    int exit_status;

    run_auth_dialog(path, args, stdin_no_password, &stdout_buf, &exit_status);
    g_assert_cmpint(exit_status, !=, 0);
}

static void
test_rejects_missing_arguments(gconstpointer user_data)
{
    const char *path = user_data;
    g_autofree char *stdout_buf = NULL;
    int exit_status;

    run_auth_dialog(path, NULL, stdin_no_password, &stdout_buf, &exit_status);
    g_assert_cmpint(exit_status, !=, 0);
}

static void
test_external_ui_asks_for_missing_password(gconstpointer user_data)
{
    const char *path = user_data;
    const char *args[] = {"-n", "Test", "-u", "11111111-1111-1111-1111-111111111111",
                          "-s", SNX_TEST_SERVICE, "--external-ui-mode", NULL};
    g_autofree char *stdout_buf = NULL;
    g_autoptr(GKeyFile) keyfile = g_key_file_new();
    g_autoptr(GError) error = NULL;
    int exit_status;

    run_auth_dialog(path, args, stdin_no_password, &stdout_buf, &exit_status);
    g_assert_cmpint(exit_status, ==, 0);

    g_assert_true(g_key_file_load_from_data(keyfile, stdout_buf, -1, G_KEY_FILE_NONE, &error));
    g_assert_no_error(error);
    g_assert_cmpstr(g_key_file_get_string(keyfile, "VPN Plugin UI", "Version", NULL), ==, "2");
    g_assert_true(g_key_file_get_boolean(keyfile, "password", "ShouldAsk", NULL));
}

static void
test_external_ui_skips_known_password(gconstpointer user_data)
{
    const char *path = user_data;
    const char *args[] = {"-n", "Test", "-u", "11111111-1111-1111-1111-111111111111",
                          "-s", SNX_TEST_SERVICE, "--external-ui-mode", NULL};
    g_autofree char *stdout_buf = NULL;
    g_autoptr(GKeyFile) keyfile = g_key_file_new();
    g_autoptr(GError) error = NULL;
    int exit_status;

    run_auth_dialog(path, args, stdin_with_password, &stdout_buf, &exit_status);
    g_assert_cmpint(exit_status, ==, 0);

    g_assert_true(g_key_file_load_from_data(keyfile, stdout_buf, -1, G_KEY_FILE_NONE, &error));
    g_assert_no_error(error);
    g_assert_false(g_key_file_get_boolean(keyfile, "password", "ShouldAsk", NULL));
    g_assert_cmpstr(g_key_file_get_string(keyfile, "password", "Value", NULL), ==, "hunter2");
}

static void
test_external_ui_reprompt_forces_ask(gconstpointer user_data)
{
    const char *path = user_data;
    const char *args[] = {"-n", "Test", "-u", "11111111-1111-1111-1111-111111111111",
                          "-s", SNX_TEST_SERVICE, "--external-ui-mode", "--reprompt", NULL};
    g_autofree char *stdout_buf = NULL;
    g_autoptr(GKeyFile) keyfile = g_key_file_new();
    g_autoptr(GError) error = NULL;
    int exit_status;

    run_auth_dialog(path, args, stdin_with_password, &stdout_buf, &exit_status);
    g_assert_cmpint(exit_status, ==, 0);

    g_assert_true(g_key_file_load_from_data(keyfile, stdout_buf, -1, G_KEY_FILE_NONE, &error));
    g_assert_no_error(error);
    g_assert_true(g_key_file_get_boolean(keyfile, "password", "ShouldAsk", NULL));
}

static void
test_external_ui_challenge_hint_uses_mfa_label(gconstpointer user_data)
{
    const char *path = user_data;
    const char *args[] = {"-n",
                          "Test",
                          "-u",
                          "11111111-1111-1111-1111-111111111111",
                          "-s",
                          SNX_TEST_SERVICE,
                          "--external-ui-mode",
                          "--reprompt",
                          "--hint",
                          "x-snx-challenge",
                          NULL};
    g_autofree char *stdout_buf = NULL;
    g_autoptr(GKeyFile) keyfile = g_key_file_new();
    g_autoptr(GError) error = NULL;
    int exit_status;

    run_auth_dialog(path, args, stdin_with_password, &stdout_buf, &exit_status);
    g_assert_cmpint(exit_status, ==, 0);

    g_assert_true(g_key_file_load_from_data(keyfile, stdout_buf, -1, G_KEY_FILE_NONE, &error));
    g_assert_no_error(error);
    g_assert_true(g_key_file_get_boolean(keyfile, "password", "ShouldAsk", NULL));
    g_assert_cmpstr(g_key_file_get_string(keyfile, "password", "Label", NULL), ==, "MFA code");
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_assert_cmpint(argc, ==, 2);

    g_test_add_data_func("/auth-dialog/rejects-wrong-service", argv[1], test_rejects_wrong_service);
    g_test_add_data_func("/auth-dialog/rejects-missing-arguments", argv[1], test_rejects_missing_arguments);
    g_test_add_data_func("/auth-dialog/external-ui-asks-for-missing-password",
                         argv[1],
                         test_external_ui_asks_for_missing_password);
    g_test_add_data_func("/auth-dialog/external-ui-skips-known-password",
                         argv[1],
                         test_external_ui_skips_known_password);
    g_test_add_data_func("/auth-dialog/external-ui-reprompt-forces-ask",
                         argv[1],
                         test_external_ui_reprompt_forces_ask);
    g_test_add_data_func("/auth-dialog/external-ui-challenge-hint-uses-mfa-label",
                         argv[1],
                         test_external_ui_challenge_hint_uses_mfa_label);

    return g_test_run();
}
