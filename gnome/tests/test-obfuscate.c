/* SPDX-License-Identifier: MIT */
/* Copyright (C) 2026 Leandro Vital <leavitals@gmail.com> */

#include "snx-obfuscate.h"

#include "snx-errors.h"

#include <glib.h>
#include <string.h>

static void
assert_obfuscate(const char *plain, const char *expected_hex)
{
    g_autofree char *hex = snx_obfuscate((const guint8 *) plain, strlen(plain));

    g_assert_cmpstr(hex, ==, expected_hex);
}

static void
assert_round_trip(const char *plain)
{
    g_autofree char *hex = snx_obfuscate((const guint8 *) plain, strlen(plain));
    g_autoptr(GError) error = NULL;
    g_autofree guint8 *decoded = NULL;
    gsize decoded_len = 0;

    g_assert_true(snx_deobfuscate(hex, &decoded, &decoded_len, &error));
    g_assert_no_error(error);
    g_assert_cmpuint(decoded_len, ==, strlen(plain));
    g_assert_cmpint(memcmp(decoded, plain, decoded_len), ==, 0);
}

/* Exact hex fixtures independently derived from analysis of the Check
 * Point credential obfuscation algorithm, not copied from any captured
 * network traffic. */
static void
test_known_vectors(void)
{
    assert_obfuscate("password", "203726313a372e5d");
    assert_obfuscate("hunter2", "773b233d2a3a45");
    assert_obfuscate("a", "4c");
    assert_obfuscate("", "");
}

static void
test_round_trip(void)
{
    assert_round_trip("password");
    assert_round_trip("hunter2");
    assert_round_trip("user@corp.example.com");
    assert_round_trip("a");
    assert_round_trip("");
    assert_round_trip("!@#$%^&*()_+-=[]{}|;:,.<>?/~`");
}

static void
test_deobfuscate_rejects_bad_input(void)
{
    g_autoptr(GError) error = NULL;
    guint8 *decoded = NULL;
    gsize decoded_len = 0;

    g_assert_false(snx_deobfuscate("abc", &decoded, &decoded_len, &error));
    g_assert_error(error, SNX_ERROR, SNX_ERROR_PARSE);
    g_clear_error(&error);

    g_assert_false(snx_deobfuscate("zz", &decoded, &decoded_len, &error));
    g_assert_error(error, SNX_ERROR, SNX_ERROR_PARSE);
}

int
main(int argc, char **argv)
{
    g_test_init(&argc, &argv, NULL);
    g_test_add_func("/obfuscate/known-vectors", test_known_vectors);
    g_test_add_func("/obfuscate/round-trip", test_round_trip);
    g_test_add_func("/obfuscate/rejects-bad-input", test_deobfuscate_rejects_bad_input);
    return g_test_run();
}
