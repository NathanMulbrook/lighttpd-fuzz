#!/usr/bin/env python3
"""Live checks that selected profiles actually reach their advertised paths."""

import gzip
import importlib.util
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_normalizer():
    spec = importlib.util.spec_from_file_location(
        "lighttpd_corpus_normalizer", ROOT / "normalize-corpus-flags.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


normalizer = load_normalizer()


def exchange(port, request, read_until_close=True):
    with socket.create_connection(("127.0.0.1", port), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(request)
        response = bytearray()
        while True:
            try:
                block = sock.recv(65536)
            except socket.timeout:
                if read_until_close:
                    raise
                break
            if not block:
                break
            response.extend(block)
            if not read_until_close and b"\r\n\r\n" in response:
                break
        return bytes(response), sock if not read_until_close else None


def request(path=b"/", extra_headers=b""):
    return (
        b"GET "
        + path
        + b" HTTP/1.1\r\nHost: localhost\r\n"
        + extra_headers
        + b"Connection: close\r\n\r\n"
    )


def assert_status(response, status):
    first_line = response.split(b"\r\n", 1)[0]
    expected = b" " + str(status).encode() + b" "
    assert expected in first_line, first_line


def wait_for_profiles(supervisor):
    deadline = time.monotonic() + 20
    pending = set(range(1, 48))
    while pending and time.monotonic() < deadline:
        if supervisor.poll() is not None:
            raise AssertionError(f"run.sh exited early with {supervisor.returncode}")
        for config_id in tuple(pending):
            probe = request(b"/__fuzz_health")
            if config_id == 23:
                probe = b"PROXY UNKNOWN\r\n" + probe
            try:
                response, _ = exchange(7600 + config_id, probe)
            except OSError:
                continue
            if response.startswith(b"HTTP/"):
                pending.remove(config_id)
        if pending:
            time.sleep(0.1)
    assert not pending, f"profiles did not become ready: {sorted(pending)}"


def check_cgi_compression(config_id):
    response, _ = exchange(
        7600 + config_id,
        request(b"/cgi/echo.cgi?stream", b"Accept-Encoding: gzip\r\n"),
    )
    assert_status(response, 200)
    headers, body = response.split(b"\r\n\r\n", 1)
    assert b"content-encoding: gzip" in headers.lower(), headers
    assert b"cgi-stream-a" in gzip.decompress(body)


def check_cgi_controls():
    expected = (ROOT / "configs/docroot/files/index.txt").read_bytes()
    redirect, _ = exchange(5630, request(b"/cgi/echo.cgi?redirect"))
    assert_status(redirect, 200)
    assert expected in redirect

    xsendfile, _ = exchange(5630, request(b"/cgi/echo.cgi?xsendfile"))
    assert_status(xsendfile, 200)
    assert expected in xsendfile


def check_proxy_paths():
    proxied, _ = exchange(5622, request(b"/gateway/files/index.txt"))
    assert_status(proxied, 200)
    assert b"backend-ok" in proxied

    with socket.create_connection(("127.0.0.1", 5622), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(b"CONNECT :6501 HTTP/1.1\r\nHost: localhost\r\n\r\n")
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(sock.recv(4096))
        assert_status(bytes(response), 200)
        sock.sendall(request(b"/files/index.txt"))
        tunneled = bytearray()
        while True:
            block = sock.recv(65536)
            if not block:
                break
            tunneled.extend(block)
        assert_status(bytes(tunneled), 200)
        assert b"backend-ok" in tunneled


def check_controlled_backends():
    for path in (b"/proxy/normal", b"/fastcgi/normal", b"/scgi/normal"):
        response, _ = exchange(5621, request(path))
        assert_status(response, 200)
        assert b"backend-ok" in response, (path, response)

    partial, _ = exchange(
        5621,
        request(b"/proxy/normal", b"X-Backend-Mode: partial\r\n"),
    )
    assert_status(partial, 200)
    assert b"backend-ok" in partial

    with socket.create_connection(("127.0.0.1", 5621), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(
            b"GET /proxy/upgrade HTTP/1.1\r\nHost: proxy.example\r\n"
            b"Connection: Upgrade\r\nUpgrade: backend-echo\r\n\r\n"
        )
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(sock.recv(4096))
        assert_status(bytes(response), 101)
        sock.sendall(b"runtime-upgrade-echo")
        echoed = bytearray()
        while len(echoed) < len(b"runtime-upgrade-echo"):
            echoed.extend(sock.recv(4096))
        assert bytes(echoed) == b"runtime-upgrade-echo", echoed


def check_h2_controlled_backends():
    for path in (b"/h2-proxy/normal", b"/h2-fastcgi/normal", b"/h2-scgi/normal"):
        data = normalizer.H2_PREFACE + normalizer.h2_request_headers(b"GET", path)
        with socket.create_connection(("127.0.0.1", 5637), timeout=2) as sock:
            sock.settimeout(2)
            sock.sendall(data)
            response = bytearray()
            while b"backend-ok" not in response:
                block = sock.recv(65536)
                if not block:
                    break
                response.extend(block)
        assert b"backend-ok" in response, (path, bytes(response))


def check_haproxy_protocol():
    v1, _ = exchange(5623, b"PROXY UNKNOWN\r\n" + request())
    assert_status(v1, 200)

    signature = bytes.fromhex("0d0a0d0a000d0a515549540a")
    addresses = bytes((192, 0, 2, 1, 127, 0, 0, 1))
    v2_header = signature + bytes.fromhex("2111000c") + addresses
    v2_header += (12345).to_bytes(2, "big") + (5623).to_bytes(2, "big")
    v2, _ = exchange(5623, v2_header + request())
    assert_status(v2, 200)


def check_webdav_symlink():
    propfind = (
        b"PROPFIND /dav/ HTTP/1.1\r\nHost: localhost\r\nDepth: 1\r\n"
        b"Content-Length: 0\r\nConnection: close\r\n\r\n"
    )
    response, _ = exchange(5634, propfind)
    assert_status(response, 207)
    assert b"static-link.txt" in response


def check_websocket_profiles():
    with socket.create_connection(("127.0.0.1", 5640), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(normalizer.WSTUNNEL_UPGRADE)
        response = bytearray()
        while b"\r\n\r\n" not in response:
            response.extend(sock.recv(4096))
        assert_status(bytes(response), 101)
        sock.sendall(normalizer.WSTUNNEL_BACKEND_FRAME)
        while b"backend-ok" not in response:
            block = sock.recv(65536)
            if not block:
                break
            response.extend(block)
        assert b"backend-ok" in response, bytes(response)

    with socket.create_connection(("127.0.0.1", 5642), timeout=2) as sock:
        sock.settimeout(2)
        sock.sendall(normalizer.H2_WSTUNNEL_REQUEST)
        response = bytearray()
        while b"backend-ok" not in response:
            block = sock.recv(65536)
            if not block:
                break
            response.extend(block)
        assert b"backend-ok" in response, bytes(response)


def check_added_profiles():
    response, _ = exchange(5641, request(b"/normal"))
    assert_status(response, 200)
    assert b"backend-ok" in response

    put = (
        b"PUT /dav/runtime-auth.txt HTTP/1.1\r\nHost: localhost\r\n"
        b"Authorization: Basic ZnV6ejpmdXp6\r\nContent-Length: 4\r\n"
        b"Connection: close\r\n\r\nseed"
    )
    response, _ = exchange(5643, put)
    assert_status(response, 201)

    response, _ = exchange(
        5644,
        b"GET /legacy-proxy/normal HTTP/1.1\r\nHost: legacy.example\r\n"
        b"Connection: close\r\n\r\n",
    )
    assert_status(response, 200)
    assert b"backend-ok" in response

    response, _ = exchange(
        5645,
        b"GET /route-rewrite/index.txt HTTP/1.1\r\nHost: routes.example\r\n"
        b"Connection: close\r\n\r\n",
    )
    assert_status(response, 200)
    assert b"virtual-host rewrite coverage" in response

    response, _ = exchange(5646, request(b"/ssi/exec.shtml"))
    assert_status(response, 200)
    assert b"ssi-exec-ok" in response


def main():
    with tempfile.TemporaryFile() as output:
        supervisor = subprocess.Popen(
            [str(ROOT / "run.sh"), "--fuzz"],
            cwd=ROOT,
            stdout=output,
            stderr=subprocess.STDOUT,
        )
        try:
            wait_for_profiles(supervisor)
            check_cgi_compression(29)
            check_cgi_compression(36)
            check_cgi_controls()
            check_controlled_backends()
            check_proxy_paths()
            check_h2_controlled_backends()
            check_haproxy_protocol()
            check_webdav_symlink()
            check_websocket_profiles()
            check_added_profiles()
        except BaseException:
            output.seek(0)
            print(output.read().decode(errors="replace"))
            raise
        finally:
            if supervisor.poll() is None:
                supervisor.send_signal(signal.SIGINT)
            try:
                supervisor.wait(timeout=15)
            except subprocess.TimeoutExpired:
                supervisor.kill()
                supervisor.wait()
        assert supervisor.returncode in (0, 130), supervisor.returncode
    print("Live runtime profile tests passed.")


if __name__ == "__main__":
    main()
