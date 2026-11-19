# SPDX-License-Identifier: LGPL-2.1-or-later

attestd = executable(
        'platformd-attestd',
        'attestd.c',
        'profile.c',
        'local.c',
        'remote.c',
        dependencies : [libsystemd, libcurl],
        install : true,
        install_dir : get_option('libexecdir'),
)

attestctl = executable(
        'attestctl',
        'attestctl.c',
        dependencies : libsystemd,
        install : true,
)

interface = 'io.platformd.Attest.varlink'
install_data(interface, install_dir : get_option('datadir') / 'varlink')

test('profile', executable('test-profile', 'test-profile.c', dependencies : libsystemd))
test('local', executable('test-local', 'test-local.c', dependencies : libsystemd))
test('attestd-wire', executable('test-attestd', 'test-attestd.c', dependencies : libsystemd))
test('attestctl-help', attestctl, args : ['--help'])

python = find_program('python3')
test_attestctl = executable(
        'test-attestctl',
        'attestctl.c',
        'test-attestctl.c',
        dependencies : libsystemd,
        link_args : ['-Wl,--wrap=sd_varlink_get_peer_uid'],
)
test('attestctl-wire', python, args : ['-I', '-B', files('test-attestctl.py'), test_attestctl, attestctl])

test_remote = executable('test-remote', 'test-remote.c', 'remote.c', dependencies : [libsystemd, libcurl])
test('remote', python, args : ['-I', '-B', files('test-remote.py'), test_remote], timeout : 60)
varlinkctl = find_program('varlinkctl', required : false)
if varlinkctl.found()
        test('interface', varlinkctl, args : ['validate-idl', files(interface)])
endif
