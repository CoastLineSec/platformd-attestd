#!/usr/bin/env python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import base64
import errno
import json
import os
import socket
import subprocess
import sys
import tempfile
from pathlib import Path


TIMEOUT = 5
REQUEST = {
    "method": "io.platformd.Attest.Read",
    "parameters": {"profile": "protected-read"},
    "more": True,
}


def notice(message):
    return {"continues": True, "parameters": {"message": message}}


def grant(data):
    return {"parameters": {"status": "granted", "dataBase64": base64.b64encode(data).decode("ascii")}}


def read_request(connection):
    call = bytearray()
    while b"\0" not in call:
        chunk = connection.recv(4096 - len(call))
        assert chunk, "Missing client request"
        call.extend(chunk)
    message, trailing = call.split(b"\0", 1)
    assert not trailing
    assert json.loads(message) == REQUEST


def call(path, mode, replies):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        try:
            listener.listen(1)
            listener.settimeout(TIMEOUT)
            with subprocess.Popen([sys.argv[1], path, mode], stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
                try:
                    connection, _ = listener.accept()
                    with connection:
                        connection.settimeout(TIMEOUT)
                        if mode == "untrusted":
                            assert connection.recv(1) == b""
                        else:
                            read_request(connection)
                            connection.sendall(b"".join(json.dumps(reply).encode("utf-8") + b"\0" for reply in replies))
                            if mode in ("cancel", "timeout"):
                                try:
                                    assert connection.recv(1) == b""
                                except ConnectionResetError:
                                    pass
                    out, err = process.communicate(timeout=TIMEOUT)
                    return process.returncode, out, err
                finally:
                    if process.poll() is None:
                        process.kill()
        finally:
            path.unlink()


def assert_error(result, error=None, notices=b""):
    code, out, err = result
    assert code == 1 and out == b"", (code, len(out), err)
    assert err.startswith(notices + b"error:"), err
    reported = int(err[len(notices) + len(b"error:"):])
    assert reported > 0 and (error is None or reported == error), reported


def main():
    with tempfile.TemporaryDirectory(prefix="attest-viewer.", dir="/tmp") as directory:
        path = Path(directory) / "io.platformd.Attest"
        document = "Protected résumé\n\tExample\n".encode("utf-8")
        markup = "<b>Verification information</b>"
        message = f"message:{markup}\n".encode("utf-8")

        assert call(path, "read", [notice(markup), grant(document)]) == (0, document, message)
        assert_error(call(path, "read", [{"error": "io.platformd.Attest.Denied"}]), errno.EACCES)
        assert_error(call(path, "read", [notice("Message\nwith control"), grant(document)]), errno.EBADMSG)
        assert_error(call(path, "read", []), errno.ENOTCONN)
        assert_error(call(path, "timeout", []), errno.ETIMEDOUT)
        assert_error(call(path, "read", [{"parameters": {"status": "granted", "dataBase64": "%%%"}}]), errno.EBADMSG)

        for data in (b"", b"ab\x00cd", b"ab\x1bcd", b"ab\xffcd", b"x" * (1024 * 1024 + 1)):
            assert_error(call(path, "read", [grant(data)]), errno.EBADMSG)

        for replies in ([notice(markup)], [notice(markup), grant(document)]):
            assert_error(call(path, "cancel", replies), errno.ECANCELED, message)

        for mode, error in (("read", errno.ENOENT), ("pre-cancel", errno.ECANCELED)):
            result = subprocess.run([sys.argv[1], path, mode], capture_output=True, timeout=TIMEOUT)
            assert_error((result.returncode, result.stdout, result.stderr), error)

        if os.geteuid() != 0:
            assert_error(call(path, "untrusted", []), errno.EPERM)


if __name__ == "__main__":
    main()
