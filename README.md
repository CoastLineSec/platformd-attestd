# platformd-attestd

platformd-attestd is an optional broker for application-requested platform
attestation. It coordinates a request from a local login session with an
administrator-approved remote verifier.

## Requirements

Attestation requests require systemd-logind, platformd-verifyd,
platformd-trustd with TPM attestation support, and a remote verifier that has
enrolled the device.

The build requires libsystemd 257 or newer, libcurl 7.85 or newer with TLS 1.3
support, Meson 1.1 or newer, Ninja, and a C11 compiler. The tests require Python 3
and the OpenSSL command line tools.

## Building

```sh
meson setup build --prefix=/usr
meson compile -C build
meson test -C build
sudo meson install -C build
```

## Usage

Configure `/etc/platformd/attestd.conf` and set the socket group to permit the
configured caller. The broker accepts the `protected-read` profile on the local
Varlink socket. `attestctl read` writes the authorized resource to standard
output.

See `platformd-attestd(8)` for verifier configuration and evidence disclosure.

## License

LGPL-2.1-or-later
