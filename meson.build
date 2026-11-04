project('vortex', 'c',
    version: run_command('./version.sh').stdout(),
    license: 'BSD-3-Clause',
    default_options : [
      'buildtype=debugoptimized',
      'c_std=gnu99'
    ]
)

cc = meson.get_compiler('c')

prefix = get_option('prefix')
bindir = join_paths(prefix, get_option('bindir'))

conf_data = configuration_data()
conf_data.set('prefix', prefix)
conf_data.set('bindir', bindir)

add_global_arguments('-DPACKAGE_NAME="'+meson.project_name()+'"', language : 'c')

# libsodium: a system one if there is one, otherwise the copy that ships in ./libsodium,
# built by sodium.sh (out of tree, into ./.sodium) and linked statically.
bundled = get_option('bundled_libsodium')
sodium_dep = dependency('libsodium', version : '>=1.0.4', required : false)

if bundled.enabled() or (bundled.auto() and not sodium_dep.found())
  sodium_root = meson.current_source_dir()
  sodium_target = custom_target('libsodium',
    output : 'libsodium.stamp',
    command : [find_program('sh'), '-c', 'sh "$0/sodium.sh" && touch "$1"',
               sodium_root, '@OUTPUT@'],
    build_by_default : true)
  sodium_dep = declare_dependency(
    compile_args : ['-I' + sodium_root / '.sodium/build/src/libsodium/include'],
    link_args : [sodium_root / '.sodium/build/src/libsodium/.libs/libsodium.a'],
    sources : sodium_target)
elif not sodium_dep.found()
  error('libsodium not found, and bundled_libsodium is disabled')
endif

executable('vortex', install: true,
  sources: [
    'argz/argz.c',
    'vmux/aegis256/aegis256.c',
    'vmux/vmux.c',
    'src/argz.c',
    'src/bench.c',
    'src/bind.c',
    'src/common.c',
    'src/ctl.c',
    'src/hub.c',
    'src/iface.c',
    'src/keygen.c',
    'src/list.c',
    'src/main.c',
    'src/netlink.c',
    'src/path.c',
    'src/path_manager.c',
    'src/peer.c',
    'src/set.c',
    'src/show.c',
    'src/tun.c',
    'src/version.c',
  ],
  dependencies: [
    sodium_dep,
    dependency('threads'),
  ]
)

systemd = dependency('systemd', required: false)

if systemd.found()
  systemdutildir = systemd.get_pkgconfig_variable('systemdutildir')
  configure_file(
      input: 'systemd/vortex@.service.in',
      output: 'vortex@.service',
      configuration: conf_data,
      install_dir: join_paths(systemdutildir, 'system')
  )
  configure_file(
      input: 'systemd/vortex-hub@.service.in',
      output: 'vortex-hub@.service',
      configuration: conf_data,
      install_dir: join_paths(systemdutildir, 'system')
  )
  install_data('systemd/vortex.network',
      install_dir: join_paths(systemdutildir, 'network'))
  install_data('systemd/vortex-client.network',
      install_dir: join_paths(systemdutildir, 'network'))
  install_data('systemd/vortex-run',
      install_dir: bindir)
  install_data('systemd/vortex-setup',
      install_dir: bindir)
endif
