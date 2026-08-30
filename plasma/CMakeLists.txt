# SPDX-License-Identifier: MIT
# Copyright (C) 2026 Leandro Vital <leavitals@gmail.com>
#
# Builds only the plasma-nm VPN editor/secret-agent plugin for KDE Plasma.
# The core NetworkManager SNX backend (nm-snx-service, the snx.name VPN type
# registration, the D-Bus policy) lives in the common networkmanager-snx
# package (../common/) and is a runtime dependency of this one -- see
# ../common/meson.build and ../common/PKGBUILD. This plugin still compiles a
# `snx-core` static library and the shared core tests directly from the
# common src/ for its own test suite below, but does not install nm-snx-service
# or snx.name itself, so it no longer conflicts with gnome/'s package.
#
# This is intentionally its own CMake project, separate from gnome/
# (Meson/C99): the UI plugin targets Qt6/KF6, and plasma-nm itself is a
# CMake/ECM project, so building this piece the same way keeps it close to
# how it would look if it were ever merged upstream into plasma-nm's own
# vpn/ tree (see vendor/vpnuiplugin.h for why it isn't).
#
# Build:
#   cmake -S plasma -B plasma/build -DCMAKE_INSTALL_PREFIX=/usr
#   cmake --build plasma/build
#   sudo cmake --install plasma/build

cmake_minimum_required(VERSION 3.16)
project(plasmanetworkmanagement_snxui C CXX)

include(GNUInstallDirs)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 99)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets DBus Concurrent)
find_package(KF6CoreAddons REQUIRED)
find_package(KF6WidgetsAddons REQUIRED)
find_package(KF6NetworkManagerQt REQUIRED)

find_package(PkgConfig REQUIRED)
pkg_check_modules(GLIB REQUIRED IMPORTED_TARGET glib-2.0 gio-2.0)
pkg_check_modules(LIBNM REQUIRED IMPORTED_TARGET libnm)

# plasmanm_editor/plasmanm_internal are plasma-nm's own private
# implementation libraries: runtime .so only, no CMake package config, no
# pkg-config file (see vendor/vpnuiplugin.h). Locate the already-installed
# runtime library directly.
find_library(PLASMANM_EDITOR_LIBRARY NAMES plasmanm_editor)
if(NOT PLASMANM_EDITOR_LIBRARY)
  message(FATAL_ERROR
    "libplasmanm_editor.so not found. Install the plasma-nm package "
    "(it ships this runtime library even though it does not ship its "
    "headers) before building this plugin.")
endif()

find_program(QMAKE6_EXECUTABLE NAMES qmake6 qmake-qt6 qmake)
if(NOT QMAKE6_EXECUTABLE)
  message(FATAL_ERROR "qmake6 not found; needed to locate Qt's plugin install directory")
endif()
execute_process(
  COMMAND "${QMAKE6_EXECUTABLE}" -query QT_INSTALL_PLUGINS
  OUTPUT_VARIABLE QT6_INSTALL_PLUGINS
  OUTPUT_STRIP_TRAILING_WHITESPACE
)
set(SNX_KDE_VPN_PLUGIN_DIR "${QT6_INSTALL_PLUGINS}/plasma/network/vpn")

# Reuses networkmanager-snx's own gateway/login-type discovery code (pure
# C99 + GLib/GIO, no libnm dependency) for the "Query..." button, instead of
# reimplementing the CCC HTTPS handshake in Qt. Only the discovery subset is
# needed here, not the tunnel/TUN/netlink pieces nm-snx-service links.
set(SNX_CORE_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../src")
set(SNX_DISCOVERY_SOURCES
  "${SNX_CORE_DIR}/snx-ccc.c"
  "${SNX_CORE_DIR}/snx-errors.c"
  "${SNX_CORE_DIR}/snx-obfuscate.c"
  "${SNX_CORE_DIR}/snx-sexpr.c"
  "${SNX_CORE_DIR}/snx-sexpr-writer.c"
)
set_source_files_properties(${SNX_DISCOVERY_SOURCES} PROPERTIES LANGUAGE C)

add_library(plasmanetworkmanagement_snxui MODULE
  snx.cpp
  snx.h
  snxwidget.cpp
  snxwidget.h
  snx.ui
  snxadvancedwidget.cpp
  snxadvancedwidget.h
  snxadvanced.ui
  snxauth.cpp
  snxauth.h
  snxauth.ui
  ${SNX_DISCOVERY_SOURCES}
)

target_include_directories(plasmanetworkmanagement_snxui PRIVATE
  "${CMAKE_CURRENT_SOURCE_DIR}"
  "${CMAKE_CURRENT_SOURCE_DIR}/vendor"
  "${SNX_CORE_DIR}"
)

target_link_libraries(plasmanetworkmanagement_snxui PRIVATE
  Qt6::Core
  Qt6::Widgets
  Qt6::DBus
  Qt6::Concurrent
  KF6::CoreAddons
  KF6::WidgetsAddons
  KF6::NetworkManagerQt
  PkgConfig::GLIB
  PkgConfig::LIBNM
  "${PLASMANM_EDITOR_LIBRARY}"
)

set_target_properties(plasmanetworkmanagement_snxui PROPERTIES PREFIX "")

install(TARGETS plasmanetworkmanagement_snxui DESTINATION "${SNX_KDE_VPN_PLUGIN_DIR}")

# snx-core: compiled here purely so the shared core tests below can link it
# (mirroring gnome/meson.build's own snx_core static library). The D-Bus VPN
# service (nm-snx-service), the snx.name registration, and the D-Bus policy
# are NOT built or installed here -- they live in the common
# networkmanager-snx package (../common/), a runtime dependency of this
# plugin (see PKGBUILD), so this package no longer conflicts with gnome/'s.
set(SNX_CORE_LIB_SOURCES
  "${SNX_CORE_DIR}/snx-errors.c"
  "${SNX_CORE_DIR}/snx-config.c"
  "${SNX_CORE_DIR}/snx-ip4-config.c"
  "${SNX_CORE_DIR}/snx-sexpr.c"
  "${SNX_CORE_DIR}/snx-sexpr-writer.c"
  "${SNX_CORE_DIR}/snx-obfuscate.c"
  "${SNX_CORE_DIR}/snx-ccc.c"
  "${SNX_CORE_DIR}/snx-slim.c"
  "${SNX_CORE_DIR}/snx-tun.c"
  "${SNX_CORE_DIR}/snx-netlink.c"
  "${SNX_CORE_DIR}/snx-ssl-tunnel.c"
)
set_source_files_properties(${SNX_CORE_LIB_SOURCES} PROPERTIES LANGUAGE C)

add_library(snx-core STATIC ${SNX_CORE_LIB_SOURCES})
set_target_properties(snx-core PROPERTIES AUTOMOC OFF AUTOUIC OFF)
target_include_directories(snx-core PUBLIC "${SNX_CORE_DIR}")
target_link_libraries(snx-core PUBLIC PkgConfig::GLIB PkgConfig::LIBNM)

# ---- tests and valgrind ----
#
# Reuses the same core tests gnome/meson.build runs (gnome/tests/test-*.c):
# config, ip4-config, sexpr, sexpr-writer, obfuscate, ccc, slim all test
# snx-core directly and have no GTK dependency, so they apply here
# unchanged. test-editor-plugin.c/test-auth-dialog.c are GTK-specific
# (they load libnm-vpn-plugin-snx.so and spawn the GTK auth dialog, which
# this build doesn't produce) and have no plasma/ equivalent.
find_program(VALGRIND_EXECUTABLE valgrind)
if(VALGRIND_EXECUTABLE)
  set(MEMORYCHECK_COMMAND "${VALGRIND_EXECUTABLE}")
  set(MEMORYCHECK_COMMAND_OPTIONS
    "--leak-check=full --show-leak-kinds=definite,indirect --errors-for-leak-kinds=definite,indirect --error-exitcode=1")
endif()
include(CTest)

set(SNX_TESTS_DIR "${CMAKE_CURRENT_SOURCE_DIR}/../gnome/tests")
set(SNX_TEST_NAMES config ip4-config sexpr sexpr-writer obfuscate ccc slim)
set(SNX_TEST_TARGETS "")

foreach(SNX_TEST_NAME ${SNX_TEST_NAMES})
  set(SNX_TEST_TARGET "test-${SNX_TEST_NAME}")
  set(SNX_TEST_SOURCE "${SNX_TESTS_DIR}/${SNX_TEST_TARGET}.c")

  set_source_files_properties("${SNX_TEST_SOURCE}" PROPERTIES LANGUAGE C)
  add_executable(${SNX_TEST_TARGET} "${SNX_TEST_SOURCE}")
  set_target_properties(${SNX_TEST_TARGET} PROPERTIES AUTOMOC OFF AUTOUIC OFF)
  target_link_libraries(${SNX_TEST_TARGET} PRIVATE snx-core)

  add_test(NAME ${SNX_TEST_NAME} COMMAND ${SNX_TEST_TARGET})
  list(APPEND SNX_TEST_TARGETS ${SNX_TEST_TARGET})
endforeach()

if(VALGRIND_EXECUTABLE)
  # ctest does not build anything itself, so without this dependency
  # `cmake --build plasma/build --target valgrind` as a first/standalone build
  # step would fail with "Could not find executable test-config" etc.
  add_custom_target(valgrind
    COMMAND ${CMAKE_CTEST_COMMAND} --output-on-failure -T memcheck
    WORKING_DIRECTORY "${CMAKE_BINARY_DIR}"
    COMMENT "Running tests under Valgrind"
  )
  add_dependencies(valgrind ${SNX_TEST_TARGETS})
endif()
