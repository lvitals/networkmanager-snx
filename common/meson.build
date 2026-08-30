project(
  'networkmanager-snx',
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

common_deps = [
  glib_dep,
  gio_dep,
  gio_unix_dep,
  libnm_dep,
]

src_inc = include_directories('../src')
libdir = get_option('libdir')
nm_libexecdir = join_paths(get_option('prefix'), libdir, 'NetworkManager')
nm_vpndir = join_paths(get_option('prefix'), libdir, 'NetworkManager', 'VPN')

conf = configuration_data()
conf.set('NM_SNX_SERVICE_PATH', join_paths(nm_libexecdir, 'nm-snx-service'))
conf.set('NM_SNX_PLUGIN_PATH', join_paths(nm_libexecdir, 'libnm-vpn-plugin-snx.so'))
conf.set('NM_SNX_AUTH_DIALOG_PATH', join_paths(nm_libexecdir, 'nm-snx-auth-dialog'))

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

executable(
  'nm-snx-service',
  files('../src/nm-snx-service.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
  install: true,
  install_dir: nm_libexecdir,
)

executable(
  'nm-snx-discover',
  files('../src/nm-snx-discover.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
  install: true,
  install_dir: get_option('bindir'),
)

executable(
  'nm-snx-tun-test',
  files('../src/nm-snx-tun-test.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
  install: false,
)

# Always carries the [libnm]/[GNOME] sections, pointing at the GTK editor
# plugin/auth dialog paths, even though this package doesn't build or install
# either: harmless if networkmanager-snx-gnome is never installed (GNOME
# Settings just won't find an SNX editor plugin), and means installing
# networkmanager-snx-gnome later doesn't require reinstalling this package.
# KDE Plasma ignores these sections entirely -- it discovers VPN UI plugins
# through their own JSON metadata (see ../plasma/plasmanetworkmanagement_snxui.json).
configure_file(
  input: '../src/data/snx.name.in',
  output: 'snx.name',
  configuration: conf,
  install: true,
  install_dir: nm_vpndir,
)

install_data(
  '../src/data/nm-snx-service.conf',
  install_dir: join_paths(get_option('datadir'), 'dbus-1', 'system.d'),
)

test_config = executable(
  'test-config',
  files('../gnome/tests/test-config.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test_ip4_config = executable(
  'test-ip4-config',
  files('../gnome/tests/test-ip4-config.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test_sexpr = executable(
  'test-sexpr',
  files('../gnome/tests/test-sexpr.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test_sexpr_writer = executable(
  'test-sexpr-writer',
  files('../gnome/tests/test-sexpr-writer.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test_obfuscate = executable(
  'test-obfuscate',
  files('../gnome/tests/test-obfuscate.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test_ccc = executable(
  'test-ccc',
  files('../gnome/tests/test-ccc.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test_slim = executable(
  'test-slim',
  files('../gnome/tests/test-slim.c'),
  include_directories: src_inc,
  link_with: snx_core,
  dependencies: common_deps,
)

test('config', test_config)
test('ip4-config', test_ip4_config)
test('sexpr', test_sexpr)
test('sexpr-writer', test_sexpr_writer)
test('obfuscate', test_obfuscate)
test('ccc', test_ccc)
test('slim', test_slim)

run_target(
  'valgrind',
  command: [
    find_program('meson'),
    'test',
    '--print-errorlogs',
    '--wrap=valgrind --leak-check=full --show-leak-kinds=definite,indirect --errors-for-leak-kinds=definite,indirect --error-exitcode=1',
  ],
)
