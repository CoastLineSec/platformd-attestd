# platformd-attestd

platformd-attestd is an optional broker for application-requested platform
attestation. It coordinates a request from a local login session with an
administrator-approved remote verifier.

## Requirements

Attestation requests require systemd-logind, platformd-verifyd,
platformd-trustd with TPM attestation support, and a remote verifier that has
enrolled the device.

## Building

This checkout contains package metadata and documentation.

## Usage

Each request is bound to the caller's login session and the verifier's
challenge. The relying service applies its own policy to authorize the
requested operation.

## License

LGPL-2.1-or-later
