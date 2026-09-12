#!/usr/bin/env python3
"""Protocol-level tests for the deterministic backend fixture."""

import concurrent.futures
import importlib.util
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load_backend():
    spec = importlib.util.spec_from_file_location(
        "backend_responder", ROOT / "backend-responder.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


backend = load_backend()


def connect(port):
    deadline = time.monotonic() + 5
    while True:
        try:
            sock = socket.create_connection(("127.0.0.1", port), timeout=0.5)
            sock.settimeout(2)
            return sock
        except OSError:
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.02)


def exchange(port, data):
    with connect(port) as sock:
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        response = bytearray()
        while True:
            try:
                block = sock.recv(65536)
            except ConnectionResetError:
                return bytes(response)
            if not block:
                return bytes(response)
            response.extend(block)


def read_headers(sock):
    response = bytearray()
    while b"\r\n\r\n" not in response:
        block = sock.recv(4096)
        if not block:
            break
        response.extend(block)
    return bytes(response)


def http_request(path, headers=(), body=b""):
    fields = b"".join(name + b": " + value + b"\r\n" for name, value in headers)
    if body and not any(name.lower() == b"content-length" for name, _ in headers):
        fields += b"Content-Length: " + str(len(body)).encode() + b"\r\n"
    return (b"GET " + path + b" HTTP/1.1\r\nHost: fixture\r\n" + fields
            + b"Connection: close\r\n\r\n" + body)


def fcgi_name_value(name, value):
    name = name if isinstance(name, bytes) else name.encode()
    value = value if isinstance(value, bytes) else value.encode()
    return (backend._fcgi_length(len(name)) + backend._fcgi_length(len(value))
            + name + value)


def fcgi_request(path, mode=None, body=b"", keep=False, request_id=1):
    params = [
        fcgi_name_value("REQUEST_METHOD", "GET"),
        fcgi_name_value("REQUEST_URI", path),
        fcgi_name_value("CONTENT_LENGTH", str(len(body))),
    ]
    if mode:
        params.append(fcgi_name_value("HTTP_X_BACKEND_MODE", mode))
    begin = b"\0\1" + bytes((1 if keep else 0,)) + b"\0" * 5
    records = [
        backend.fcgi_record(1, request_id, begin),
        backend.fcgi_record(4, request_id, b"".join(params)),
        backend.fcgi_record(4, request_id),
    ]
    if body:
        records.append(backend.fcgi_record(5, request_id, body))
    records.append(backend.fcgi_record(5, request_id))
    return b"".join(records)


def parse_fcgi(data):
    records = []
    offset = 0
    while offset < len(data):
        if len(data) - offset < 8:
            raise AssertionError("truncated FastCGI response header")
        header = data[offset:offset + 8]
        length = int.from_bytes(header[4:6], "big")
        padding = header[6]
        end = offset + 8 + length + padding
        if end > len(data):
            raise AssertionError("truncated FastCGI response record")
        records.append((header[1], int.from_bytes(header[2:4], "big"),
                        data[offset + 8:offset + 8 + length]))
        offset = end
    return records


def scgi_request(path, mode=None, body=b""):
    pairs = [
        (b"CONTENT_LENGTH", str(len(body)).encode()),
        (b"SCGI", b"1"),
        (b"REQUEST_METHOD", b"GET"),
        (b"REQUEST_URI", path if isinstance(path, bytes) else path.encode()),
    ]
    if mode:
        pairs.append((b"HTTP_X_BACKEND_MODE", mode.encode()))
    headers = b"".join(key + b"\0" + value + b"\0" for key, value in pairs)
    return str(len(headers)).encode() + b":" + headers + b"," + body


class BackendProtocolTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.servers = {
            protocol: backend.BackendServer(protocol, 0, workers=8, timeout=1).start()
            for protocol in ("http", "fastcgi", "scgi")
        }

    @classmethod
    def tearDownClass(cls):
        for server in cls.servers.values():
            server.stop()

    def test_stable_mode_names_and_selection(self):
        self.assertEqual(len(backend.MODE_NAMES), len(set(backend.MODE_NAMES)))
        for prefix in backend.MODE_PATH_PREFIXES:
            self.assertEqual(
                backend.select_mode((prefix + "chunked-trailers").encode(), {}),
                "chunked-trailers",
            )
        for path in ("/backend/103", "/fcgi/103", "/scgi/103",
                     "/h2-proxy/103", "/103"):
            self.assertEqual(backend.select_mode(path, {}), "103")
        self.assertEqual(
            backend.select_mode("/backend/normal?mode=partial", {}), "partial"
        )
        self.assertEqual(
            backend.select_mode("/backend/normal", {"x-backend-mode": b"100-103"}),
            "interim",
        )
        self.assertEqual(backend.select_mode("/backend/not-a-mode", {}), "normal")

    def test_every_mode_has_a_small_deterministic_plan(self):
        for http in (False, True):
            for mode in backend.MODE_NAMES:
                with self.subTest(http=http, mode=mode):
                    first = backend.response_plan(mode, http=http, echo=b"echo")
                    second = backend.response_plan(mode, http=http, echo=b"echo")
                    self.assertEqual(first, second)
                    self.assertLess(len(first[0]), 1024)
                    self.assertTrue(first[0])

    def test_http_normal_trailers_interim_and_redirect(self):
        port = self.servers["http"].port
        normal = exchange(port, http_request(b"/backend/normal"))
        self.assertTrue(normal.startswith(b"HTTP/1.1 200 OK\r\n"))
        self.assertTrue(normal.endswith(b"backend-ok\n"))

        trailers = exchange(port, http_request(b"/backend/chunked-trailers"))
        self.assertIn(b"Transfer-Encoding: chunked\r\n", trailers)
        self.assertTrue(trailers.endswith(b"0\r\nX-Backend-Trailer: done\r\n\r\n"))

        interim = exchange(port, http_request(b"/backend/interim"))
        self.assertEqual(interim.count(b"HTTP/1.1 "), 3)
        self.assertIn(b"100 Continue", interim)
        self.assertIn(b"103 Early Hints", interim)
        self.assertTrue(interim.endswith(b"backend-ok\n"))

        redirect = exchange(port, http_request(b"/ignored", ((b"X-Backend-Mode", b"redirect-cookie"),)))
        self.assertTrue(redirect.startswith(b"HTTP/1.1 302 Found\r\n"))
        self.assertIn(b"Location: /__backend__/normal\r\n", redirect)
        self.assertIn(b"Set-Cookie: fixture=1;", redirect)

    def test_http_error_shapes_and_partial_writes(self):
        port = self.servers["http"].port
        early = exchange(port, http_request(b"/backend/early-close"))
        self.assertIn(b"Content-Length: 64\r\n", early)
        self.assertTrue(early.endswith(b"short\n"))
        self.assertLess(len(early.split(b"\r\n\r\n", 1)[1]), 64)

        malformed = exchange(port, http_request(b"/backend/malformed-headers"))
        self.assertIn(b"Header Without Colon\r\n", malformed)
        truncated = exchange(port, http_request(b"/backend/truncated-headers"))
        self.assertNotIn(b"\r\n\r\n", truncated)
        bad_chunk = exchange(port, http_request(b"/backend/malformed-chunk"))
        self.assertTrue(bad_chunk.endswith(b"Z\r\nbad\r\n0\r\n\r\n"))
        short_chunk = exchange(port, http_request(b"/backend/truncated-chunk"))
        self.assertTrue(short_chunk.endswith(b"5\r\nxy"))
        partial = exchange(port, http_request(b"/backend/partial"))
        self.assertEqual(partial, exchange(port, http_request(b"/backend/normal")))

        class RecordingSocket:
            def __init__(self):
                self.sizes = []
            def send(self, data):
                self.sizes.append(len(data))
                return len(data)

        recorder = RecordingSocket()
        backend._send(recorder, b"0123456789", partial=True)
        self.assertEqual(sum(recorder.sizes), 10)
        self.assertLessEqual(max(recorder.sizes), 3)
        self.assertGreater(len(recorder.sizes), 1)

    def test_http_upgrade_echo(self):
        response = exchange(
            self.servers["http"].port,
            http_request(b"/backend/upgrade") + b"tunnel-data",
        )
        self.assertTrue(response.startswith(b"HTTP/1.1 101 Switching Protocols\r\n"))
        self.assertTrue(response.endswith(b"tunnel-data"))

        with connect(self.servers["http"].port) as sock:
            sock.sendall(http_request(b"/backend/upgrade"))
            headers = read_headers(sock)
            self.assertTrue(
                headers.startswith(b"HTTP/1.1 101 Switching Protocols\r\n")
            )
            sock.sendall(b"delayed-tunnel-data")
            self.assertEqual(sock.recv(64), b"delayed-tunnel-data")

    def test_fastcgi_records_cover_normal_interim_and_bad_shapes(self):
        port = self.servers["fastcgi"].port
        normal = parse_fcgi(exchange(port, fcgi_request("/fcgi/normal")))
        self.assertEqual([record[0] for record in normal], [6, 6, 3])
        self.assertTrue(normal[0][2].startswith(b"Status: 200 OK\r\n"))
        self.assertTrue(normal[0][2].endswith(b"backend-ok\n"))

        interim = parse_fcgi(exchange(port, fcgi_request("/fcgi/interim")))
        output = b"".join(record[2] for record in interim if record[0] == 6)
        self.assertIn(b"Status: 100 Continue\r\n\r\n", output)
        self.assertIn(b"Status: 103 Early Hints\r\n", output)
        self.assertIn(b"Status: 200 OK\r\n", output)

        chunked = parse_fcgi(exchange(port, fcgi_request("/ignored", "chunked-trailers")))
        self.assertIn(b"X-Backend-Trailer: done", chunked[0][2])
        early = parse_fcgi(exchange(port, fcgi_request("/fcgi/early-close")))
        self.assertEqual([record[0] for record in early], [6])
        self.assertIn(b"Content-Length: 64", early[0][2])

    def test_fastcgi_reuses_a_connection_when_requested(self):
        response = exchange(
            self.servers["fastcgi"].port,
            fcgi_request("/fastcgi/normal", keep=True, request_id=7)
            + fcgi_request("/h2-fastcgi/redirect-cookie", request_id=8),
        )
        records = parse_fcgi(response)
        self.assertEqual([record[1] for record in records], [7, 7, 7, 8, 8, 8])
        second = b"".join(record[2] for record in records
                          if record[0] == 6 and record[1] == 8)
        self.assertTrue(second.startswith(b"Status: 302 Found\r\n"))

    def test_scgi_modes_and_upgrade_body_echo(self):
        port = self.servers["scgi"].port
        normal = exchange(port, scgi_request("/scgi/normal"))
        self.assertTrue(normal.startswith(b"Status: 200 OK\r\n"))
        trailers = exchange(port, scgi_request("/scgi/chunked-trailers"))
        self.assertIn(b"Transfer-Encoding: chunked", trailers)
        redirect = exchange(port, scgi_request("/ignored", "redirect-cookie"))
        self.assertTrue(redirect.startswith(b"Status: 302 Found\r\n"))
        upgrade = exchange(port, scgi_request("/scgi/upgrade", body=b"scgi-echo"))
        self.assertTrue(upgrade.startswith(b"Status: 101 Switching Protocols\r\n"))
        self.assertTrue(upgrade.endswith(b"scgi-echo"))

    def test_malformed_connections_do_not_stop_listeners(self):
        malformed = {
            "http": b"not an HTTP request\r\n\r\n",
            "fastcgi": b"\x02\x01\x00\x01\x00\x00\x00\x00",
            "scgi": b"x:not-a-netstring,",
        }
        valid = {
            "http": http_request(b"/backend/normal"),
            "fastcgi": fcgi_request("/fcgi/normal"),
            "scgi": scgi_request("/scgi/normal"),
        }
        for protocol, server in self.servers.items():
            with self.subTest(protocol=protocol):
                self.assertEqual(exchange(server.port, malformed[protocol]), b"")
                self.assertTrue(exchange(server.port, valid[protocol]))

    def test_concurrent_repeated_connections(self):
        jobs = []
        for number in range(6):
            jobs.extend((
                ("http", http_request(b"/backend/normal")),
                ("fastcgi", fcgi_request("/fcgi/normal", request_id=number + 1)),
                ("scgi", scgi_request("/scgi/normal")),
            ))
        with concurrent.futures.ThreadPoolExecutor(max_workers=18) as executor:
            futures = [
                executor.submit(exchange, self.servers[protocol].port, request)
                for protocol, request in jobs
            ]
            responses = [future.result(timeout=8) for future in futures]
        self.assertEqual(len(responses), 18)
        self.assertTrue(all(responses))


class BackendCommandTests(unittest.TestCase):
    def test_ready_file_appears_after_bind_and_is_removed_on_term(self):
        with tempfile.TemporaryDirectory() as temporary:
            ready = Path(temporary) / "backend.ready"
            process = subprocess.Popen(
                [sys.executable, str(ROOT / "backend-responder.py"),
                 "--http-port=0", "--fastcgi-port=0", "--scgi-port=0",
                 "--workers=2", "--ready-file", str(ready)],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
            )
            try:
                deadline = time.monotonic() + 5
                while not ready.exists() and process.poll() is None and time.monotonic() < deadline:
                    time.sleep(0.02)
                if not ready.exists():
                    error = process.stderr.read().decode(errors="replace")
                    self.fail(f"ready file not created; rc={process.poll()}: {error}")
                ports = dict(
                    line.split("=", 1) for line in ready.read_text().splitlines()
                )
                self.assertEqual(set(ports), {"http", "fastcgi", "scgi"})
                response = exchange(int(ports["http"]), http_request(b"/backend/normal"))
                self.assertTrue(response.startswith(b"HTTP/1.1 200 OK"))
            finally:
                if process.poll() is None:
                    process.send_signal(signal.SIGTERM)
                process.wait(timeout=5)
                process.stderr.close()
            self.assertEqual(process.returncode, 0)
            self.assertFalse(ready.exists())


if __name__ == "__main__":
    unittest.main()
