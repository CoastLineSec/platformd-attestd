# SPDX-License-Identifier: LGPL-2.1-or-later

gtk = dependency('gtk4', required : get_option('viewer'))
if not gtk.found()
        subdir_done()
endif
gio = dependency('gio-2.0')

executable(
        'platformd-attest-viewer',
        'viewer.c',
        'read.c',
        dependencies : [gtk, gio, libsystemd],
        install : true,
)
install_data('io.platformd.AttestViewer.desktop', install_dir : get_option('datadir') / 'applications')

test_read = executable(
        'test-viewer-read',
        'read.c',
        'test-read.c',
        dependencies : [gio, libsystemd],
        link_args : ['-Wl,--wrap=sd_varlink_get_peer_uid', '-Wl,--wrap=timerfd_settime'],
)
test('viewer-read', python, args : ['-I', '-B', files('test-read.py'), test_read], timeout : 30)
