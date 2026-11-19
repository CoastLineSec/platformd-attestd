#!/bin/bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -euo pipefail
[[ $# -eq 1 && ( $1 == broker || $1 == viewer ) ]]

socket=platformd-attestd.socket
unit_dir=/usr/lib/systemd/system
desktop=/usr/share/applications/io.platformd.AttestViewer.desktop
viewer=/usr/bin/platformd-attest-viewer

absent() {
        [[ ! -e $1 && ! -L $1 ]]
}

test -x /usr/bin/attestctl
test -x /usr/libexec/platformd-attestd
test -f "$unit_dir/$socket"
test -f "$unit_dir/platformd-attestd@.service"
grep -Fx 'ExecStart=/usr/libexec/platformd-attestd' "$unit_dir/platformd-attestd@.service"
[[ $(systemctl --root=/ is-enabled "$socket" || :) == disabled ]]
absent /etc/platformd/attestd.conf
absent /run/platformd-attestd/io.platformd.Attest

libraries=$(ldd /usr/libexec/platformd-attestd /usr/bin/attestctl)
if grep -E 'libgtk-4|not found' <<<"$libraries"; then
        exit 1
fi
systemd-analyze verify --man=no --generators=no "$unit_dir/$socket" "$unit_dir/platformd-attestd@.service"
varlinkctl validate-idl /usr/share/varlink/io.platformd.Attest.varlink >/dev/null
gzip -dc /usr/share/man/man8/platformd-attestd.8.gz | groff -man -Tutf8 >/dev/null
/usr/bin/attestctl --help >/dev/null

output=$(mktemp)
trap 'rm -f -- "$output"' EXIT
if /usr/bin/attestctl read >"$output"; then
        exit 1
fi
[[ ! -s $output ]]

if [[ $1 == viewer ]]; then
        test -x "$viewer"
        desktop-file-validate "$desktop"
        "$viewer" --help >/dev/null
else
        absent "$viewer"
        absent "$desktop"
fi
