#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile


TIMEOUT = 5
DENIED = b"Attestation denied or unavailable.\n"


def call(program, directory, profile, replies):
    path = str(Path(directory) / "io.platformd.Attest")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        try:
            listener.listen(1)
            listener.settimeout(TIMEOUT)
            process = subprocess.Popen([program, "--socket=" + path, "--profile=" + profile, "read"],
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(TIMEOUT)
                    call = bytearray()
                    while b"\0" not in call:
                        chunk = connection.recv(4096 - len(call))
                        assert chunk, "Missing client request"
                        call.extend(chunk)
                    message, trailing = call.split(b"\0", 1)
                    assert not trailing
                    assert json.loads(message) == {
                        "method": "io.platformd.Attest.Read",
                        "parameters": {"profile": profile},
                        "more": True,
                    }
                    for reply in replies:
                        connection.sendall(json.dumps(reply).encode() + b"\0")
                out, err = process.communicate(timeout=TIMEOUT)
                return process.returncode, out, err
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=TIMEOUT)
                process.stdout.close()
                process.stderr.close()
        finally:
            os.unlink(path)


def test_untrusted_peer(program, directory):
    path = str(Path(directory) / "untrusted")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(path)
        listener.listen(1)
        result = subprocess.run([program, "--socket=" + path, "read"], capture_output=True, timeout=TIMEOUT)
        assert (result.returncode, result.stdout, result.stderr) == (1, b"", DENIED)
        listener.settimeout(TIMEOUT)
        connection, _ = listener.accept()
        with connection:
            connection.settimeout(TIMEOUT)
            assert connection.recv(1) == b""


def main():
    fixture, installed = sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="attestctl.", dir="/tmp") as directory:
        assert call(fixture, directory, "protected-read", (
            {"continues": True, "parameters": {"message": "Fixture notification"}},
            {"parameters": {"status": "granted", "dataBase64": "YWJj"}},
        )) == (0, b"abc", b"Fixture notification\n")
        assert call(fixture, directory, "unapproved", (
            {"error": "io.platformd.Attest.Denied"},
        )) == (1, b"", DENIED)
        if os.geteuid() != 0:
            test_untrusted_peer(installed, directory)


if __name__ == "__main__":
    main()
