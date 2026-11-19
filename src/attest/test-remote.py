#!/usr/bin/python3
# SPDX-License-Identifier: LGPL-2.1-or-later

import base64
import hashlib
import http.server
import json
import os
from pathlib import Path
import resource
import ssl
import subprocess
import sys
import tempfile
import threading


def openssl(*args, **kwargs):
    return subprocess.run(["openssl", *args], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          check=True, timeout=10, **kwargs).stdout


def certificates(directory):
    root, root_key = directory / "root.pem", directory / "root.key"
    openssl("req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-nodes", "-days", "1", "-subj", "/CN=Test CA", "-keyout", root_key, "-out", root,
            "-addext", "basicConstraints=critical,CA:TRUE", "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    for serial, name in enumerate(("server", "client"), 1):
        key, request, cert, extensions = (directory / (name + suffix) for suffix in (".key", ".csr", ".pem", ".ext"))
        openssl("req", "-new", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-subj", "/CN=" + name, "-keyout", key, "-out", request)
        extensions.write_text("basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n" +
                              ("extendedKeyUsage=serverAuth\nsubjectAltName=IP:127.0.0.1\n"
                               if name == "server" else "extendedKeyUsage=clientAuth\n"), encoding="ascii")
        openssl("x509", "-req", "-in", request, "-CA", root, "-CAkey", root_key, "-days", "1",
                "-set_serial", str(serial), "-extfile", extensions, "-out", cert)
    public = openssl("x509", "-in", directory / "server.pem", "-pubkey", "-noout")
    der = openssl("pkey", "-pubin", "-outform", "DER", input=public)
    return "sha256//" + base64.b64encode(hashlib.sha256(der).digest()).decode()


class Handler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    began = False

    def log_message(self, *_args):
        pass

    def reply(self, code, content, data):
        self.send_response_only(code)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Type", content)
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self):
        self.server.requests += 1
        self.connection.settimeout(3)
        assert self.path == "/v1/read" and self.request_version == "HTTP/1.1"
        assert self.headers.get_all("Content-Type") == ["application/json"]
        assert not self.headers.get("Transfer-Encoding") and not self.headers.get("Expect")
        n = int(self.headers["Content-Length"])
        assert 0 < n <= 4096
        data = json.loads(self.rfile.read(n))
        if not self.began:
            assert data == {"action": "begin"}
            self.began = True
            self.reply(200, "application/json", b'{"request":{"sequence":1}}')
            if self.server.case == "disconnected":
                self.close_connection = True
            return

        assert data == {"action": "complete", "token": {"profile": "fixture"}}
        if self.server.case == "denied":
            self.reply(403, "application/octet-stream", b"")
        else:
            self.reply(200, "application/octet-stream", b"protected\0file\xff")
        self.close_connection = True


class Server(http.server.HTTPServer):
    def __init__(self, case, directory):
        super().__init__(("127.0.0.1", 0), Handler)
        self.case = case
        self.requests = 0
        self.connections = 0
        self.errors = []
        self.tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.tls.minimum_version = ssl.TLSVersion.TLSv1_3
        self.tls.verify_mode = ssl.CERT_REQUIRED
        self.tls.load_verify_locations(directory / "root.pem")
        self.tls.load_cert_chain(directory / "server.pem", directory / "server.key")

    def get_request(self):
        connection, address = super().get_request()
        self.connections += 1
        connection.settimeout(5)
        try:
            return self.tls.wrap_socket(connection, server_side=True), address
        except OSError:
            connection.close()
            raise

    def handle_error(self, _request, _address):
        error = sys.exc_info()[1]
        if not isinstance(error, (BrokenPipeError, ConnectionResetError)):
            self.errors.append(error)


def run_case(case, program, directory, pin, connections, requests):
    with Server(case, directory) as server:
        worker = threading.Thread(target=server.serve_forever, daemon=True)
        worker.start()
        try:
            subprocess.run([program, f"https://127.0.0.1:{server.server_port}/v1/read", directory / "root.pem",
                            directory / "client.pem", directory / "client.key", pin, case],
                           check=True, timeout=12)
        finally:
            server.shutdown()
            worker.join()
        assert server.connections == connections, (case, server.connections)
        assert server.requests == requests, (case, server.requests)
        assert not server.errors, (case, server.errors)


def main():
    assert len(sys.argv) == 2
    os.umask(0o077)
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    with tempfile.TemporaryDirectory(prefix="platformd-attestd-remote-") as temporary:
        directory = Path(temporary)
        pin = certificates(directory)
        for case, connections, requests in (
            ("granted", 1, 2), ("denied", 1, 2), ("disconnected", 1, 1), ("cancelled", 1, 1),
            ("untrusted", 1, 0), ("disallowed", 0, 0), ("expired", 0, 0),
        ):
            expected_pin = "sha256//" + "A" * 43 + "=" if case == "untrusted" else pin
            run_case(case, sys.argv[1], directory, expected_pin, connections, requests)


if __name__ == "__main__":
    main()
