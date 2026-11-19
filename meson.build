# SPDX-License-Identifier: LGPL-2.1-or-later
project('platformd-attestd', 'c',
        version : '0.1.0',
        license : 'LGPL-2.1-or-later',
        meson_version : '>= 1.1',
        default_options : [
                'c_std=gnu11',
                'warning_level=2',
        ])

add_project_arguments('-D_GNU_SOURCE', '-Wno-unused-parameter', language : 'c')

libsystemd = dependency('libsystemd', version : '>= 257')
libcurl = dependency('libcurl', version : '>= 7.85')
systemd = dependency('systemd', required : false)

subdir('src/attest')
subdir('man')

system_unit_dir = systemd.found() ? systemd.get_variable(pkgconfig : 'systemdsystemunitdir') : get_option('prefix') / 'lib/systemd/system'
conf = configuration_data()
conf.set('LIBEXECDIR', get_option('prefix') / get_option('libexecdir'))
configure_file(
        input : 'units/platformd-attestd@.service.in',
        output : 'platformd-attestd@.service',
        configuration : conf,
        install_dir : system_unit_dir,
)
install_data('units/platformd-attestd.socket', install_dir : system_unit_dir)
