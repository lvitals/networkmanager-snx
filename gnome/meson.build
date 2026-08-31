project(
  'networkmanager-snx-gnome',
  'c',
  version: '0.1.0',
  license: 'MIT',
  default_options: [
    'c_std=c99',
    'warning_level=3',
    'werror=true',
  ],
)

add_project_arguments('-Wno-pedantic', language: 'c')

glib_dep = dependency('glib-2.0')
gio_dep = dependency('gio-2.0')
gio_unix_dep = dependency('gio-unix-2.0')
libnm_dep = dependency('libnm')
gtk_dep = dependency('gtk4')
libnma_dep = dependency('libnma-gtk4')

common_deps = [
  glib_dep,
  gio_dep,
  gio_unix_dep,
  libnm_dep,
]

gtk_ui_deps = common_deps + [
  gtk_dep,
  libnma_dep,
]

src_inc = include_directories('../src')
libdir = get_option('libdir')
nm_libexecdir = join_paths(get_option('prefix'), libdir, 'NetworkManager')

# snx-core is rebuilt here (not linked against the networkmanager-snx package,
# which installs no shared library) purely to statically link into this
# package's own two targets below. The D-Bus service, snx.name, and D-Bus
# policy it also needs are provided by the networkmanager-snx package
# (../packaging/arch/common/PKGBUILD), a runtime dependency of this package --
# see ../packaging/arch/gnome/PKGBUILD.
snx_core_sources = files(
  '../src/snx-errors.c',
  '../src/snx-config.c',
  '../src/snx-ip4-config.c',
  '../src/snx-sexpr.c',
  '../src/snx-sexpr-writer.c',
  '../src/snx-obfuscate.c',
  '../src/snx-ccc.c',
  '../src/snx-slim.c',
  '../src/snx-tun.c',
  '../src/snx-netlink.c',
  '../src/snx-ssl-tunnel.c',
)

snx_core = static_library(
  'snx-core',
  snx_core_sources,
  include_directories: src_inc,
  dependencies: common_deps,
)

editor_plugin = shared_module(
  'nm-vpn-plugin-snx',
  files('nm-snx-editor-plugin.c', 'nm-snx-editor.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: gtk_ui_deps,
  name_prefix: 'lib',
  install: true,
  install_dir: nm_libexecdir,
)

auth_dialog = executable(
  'nm-snx-auth-dialog',
  files('nm-snx-auth-dialog.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: gtk_ui_deps,
  install: true,
  install_dir: nm_libexecdir,
)

test_editor_plugin = executable(
  'test-editor-plugin',
  files('tests/test-editor-plugin.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test_auth_dialog = executable(
  'test-auth-dialog',
  files('tests/test-auth-dialog.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test(
  'editor-plugin',
  test_editor_plugin,
  args: [editor_plugin.full_path()],
)
test(
  'auth-dialog',
  test_auth_dialog,
  args: [auth_dialog.full_path()],
)

run_target(
  'valgrind',
  command: [
    find_program('meson'),
    'test',
    '--print-errorlogs',
    '--wrap=valgrind --leak-check=full --show-leak-kinds=definite,indirect --errors-for-leak-kinds=definite,indirect --error-exitcode=1',
  ],
)
