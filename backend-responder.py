#!/usr/bin/env python3
"""Small deterministic HTTP, FastCGI, and SCGI backend fixture.

Select a response with the final request-path component or with the
``X-Backend-Mode: MODE`` request header.  The header takes precedence.
"""

import argparse
import os
import queue
import signal
import socket
import sys
import threading
import time
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


MODE_PATH_PREFIX = "/__backend__/"
MODE_PATH_PREFIXES = (
    MODE_PATH_PREFIX, "/backend/", "/fcgi/", "/fastcgi/", "/scgi/",
    "/h2-proxy/", "/h2-fastcgi/", "/h2-scgi/",
)
MODE_NAMES = (
    "normal",
    "chunked-trailers",
    "100",
    "103",
    "interim",
    "early-close",
    "malformed-headers",
    "truncated-headers",
    "malformed-chunk",
    "truncated-chunk",
    "redirect-cookie",
    "upgrade",
    "partial",
)

_MODE_ALIASES = {
    "100-103": "interim",
    "content-length-mismatch": "early-close",
    "length-mismatch": "early-close",
    "set-cookie-location": "redirect-cookie",
    "short-writes": "partial",
}
_MAX_HEADERS = 64 * 1024
_MAX_REQUEST = 1024 * 1024


def _mode_value(value):
    if isinstance(value, (bytes, bytearray, memoryview)):
        value = bytes(value).decode("latin-1", "replace")
    value = value.strip().lower().replace("_", "-")[:64]
    return _MODE_ALIASES.get(value, value)


def _canonical_mode(value):
    value = _mode_value(value)
    return value if value in MODE_NAMES else "normal"


def select_mode(uri, headers):
    """Return a stable response mode for an untrusted URI/header mapping."""
    header_mode = headers.get("x-backend-mode")
    if header_mode is not None:
        return _canonical_mode(header_mode)

    if isinstance(uri, (bytes, bytearray, memoryview)):
        uri = bytes(uri).decode("latin-1", "replace")
    try:
        parts = urlsplit(uri)
        query = parse_qs(parts.query, keep_blank_values=True)
        for key in ("backend-mode", "mode"):
            if query.get(key):
                return _canonical_mode(query[key][0])
        path = parts.path
    except (TypeError, ValueError):
        path = uri.split("?", 1)[0]

    final_component = path.rstrip("/").rsplit("/", 1)[-1]
    candidate = _mode_value(final_component)
    if candidate in MODE_NAMES:
        return candidate
    return "normal"


def _headers(status, fields, http):
    first = ("HTTP/1.1 " if http else "Status: ") + status + "\r\n"
    return (first + "".join(f"{key}: {value}\r\n" for key, value in fields)
            + "\r\n").encode("ascii")


def response_plan(mode, http=True, echo=b""):
    """Build bounded response bytes and transmission flags for a mode."""
    mode = _canonical_mode(mode)
    body = b"backend-ok\n"
    normal = _headers(
        "200 OK",
        (("Content-Type", "text/plain"), ("Content-Length", str(len(body))),
         ("Connection", "close")),
        http,
    ) + body

    if mode == "normal":
        return normal, False, False, False
    if mode == "partial":
        return normal, True, False, False
    if mode == "chunked-trailers":
        data = _headers(
            "200 OK",
            (("Content-Type", "text/plain"),
             ("Transfer-Encoding", "chunked"),
             ("Trailer", "X-Backend-Trailer"),
             ("Connection", "close")),
            http,
        ) + b"4\r\npart\r\n3\r\nial\r\n0\r\nX-Backend-Trailer: done\r\n\r\n"
        return data, False, False, False
    if mode in ("100", "103", "interim"):
        blocks = []
        if mode in ("100", "interim"):
            blocks.append(_headers("100 Continue", (), http))
        if mode in ("103", "interim"):
            blocks.append(_headers(
                "103 Early Hints", (("Link", "</early.css>; rel=preload"),), http
            ))
        return b"".join(blocks) + normal, False, False, False
    if mode == "early-close":
        data = _headers(
            "200 OK",
            (("Content-Type", "text/plain"), ("Content-Length", "64"),
             ("Connection", "close")),
            http,
        ) + b"short\n"
        return data, False, True, False
    if mode == "malformed-headers":
        first = b"HTTP/1.1 200 OK\r\n" if http else b"Status: 200 OK\r\n"
        return first + b"Header Without Colon\r\nContent-Length: 3\r\n\r\nbad", False, False, False
    if mode == "truncated-headers":
        first = b"HTTP/1.1 200 OK\r\n" if http else b"Status: 200 OK\r\n"
        return first + b"Content-Length: 3\r\nX-Truncated:", False, True, False
    if mode == "malformed-chunk":
        data = _headers(
            "200 OK", (("Transfer-Encoding", "chunked"),
                       ("Connection", "close")), http
        ) + b"Z\r\nbad\r\n0\r\n\r\n"
        return data, False, False, False
    if mode == "truncated-chunk":
        data = _headers(
            "200 OK", (("Transfer-Encoding", "chunked"),
                       ("Connection", "close")), http
        ) + b"5\r\nxy"
        return data, False, True, False
    if mode == "redirect-cookie":
        data = _headers(
            "302 Found",
            (("Location", MODE_PATH_PREFIX + "normal"),
             ("Set-Cookie", "fixture=1; Path=/; Domain=backend.invalid"),
             ("Content-Length", "0"), ("Connection", "close")),
            http,
        )
        return data, False, False, False
    if mode == "upgrade":
        data = _headers(
            "101 Switching Protocols",
            (("Connection", "Upgrade"), ("Upgrade", "backend-echo")),
            http,
        ) + echo[:_MAX_REQUEST]
        return data, False, False, True
    raise AssertionError(mode)


def _send(sock, data, partial=False):
    if not partial:
        sock.sendall(data)
        return
    view = memoryview(data)
    while view:
        sent = sock.send(view[:3])
        if sent <= 0:
            raise ConnectionError("short socket write")
        view = view[sent:]
        time.sleep(0.0002)


def _recv_exact(sock, length):
    data = bytearray()
    while len(data) < length:
        block = sock.recv(length - len(data))
        if not block:
            raise EOFError
        data.extend(block)
    return bytes(data)


def _recv_headers(sock):
    data = bytearray()
    while len(data) <= _MAX_HEADERS:
        block = sock.recv(min(4096, _MAX_HEADERS + 1 - len(data)))
        if not block:
            raise EOFError
        data.extend(block)
        marker = data.find(b"\r\n\r\n")
        if marker >= 0:
            end = marker + 4
            return bytes(data[:end]), bytes(data[end:])
    raise ValueError("headers too large")


def _parse_http_headers(data):
    lines = data[:-4].split(b"\r\n")
    request = lines[0].split(b" ", 2)
    if (len(request) != 3 or not request[0] or not request[1]
            or not request[2].startswith(b"HTTP/")):
        raise ValueError("invalid request line")
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        key, value = line.split(b":", 1)
        headers[key.decode("latin-1", "replace").strip().lower()] = value.strip()
    return request[1], headers


def handle_http(sock, max_request=_MAX_REQUEST):
    header_data, extra = _recv_headers(sock)
    uri, headers = _parse_http_headers(header_data)
    try:
        content_length = int(headers.get("content-length", b"0"))
    except (TypeError, ValueError):
        content_length = 0
    if content_length < 0 or content_length > max_request:
        raise ValueError("invalid content length")
    body = bytearray(extra[:content_length])
    if len(body) < content_length:
        body.extend(_recv_exact(sock, content_length - len(body)))

    mode = select_mode(uri, headers)
    tunnel = extra[content_length:]
    data, partial, close_early, upgrade = response_plan(
        mode, http=True, echo=tunnel
    )
    _send(sock, data, partial)
    if upgrade:
        prior_timeout = sock.gettimeout()
        # Leave enough time for lighttpd to forward the 101 response before the
        # client sends the next response-wait packet on a loaded fuzzing host.
        sock.settimeout(0.5)
        remaining = max_request - len(tunnel)
        try:
            while remaining > 0:
                block = sock.recv(min(4096, remaining))
                if not block:
                    break
                _send(sock, block)
                remaining -= len(block)
        except socket.timeout:
            pass
        finally:
            sock.settimeout(prior_timeout)
    return close_early or upgrade


def _fcgi_length(length):
    if length < 128:
        return bytes((length,))
    return (length | 0x80000000).to_bytes(4, "big")


def _fcgi_params(data):
    data = bytes(data)
    result = {}
    offset = 0

    def take_length():
        nonlocal offset
        if offset >= len(data):
            raise ValueError("truncated FastCGI params")
        if data[offset] & 0x80:
            if len(data) - offset < 4:
                raise ValueError("truncated FastCGI params")
            value = int.from_bytes(data[offset:offset + 4], "big") & 0x7FFFFFFF
            offset += 4
            return value
        value = data[offset]
        offset += 1
        return value

    while offset < len(data):
        name_length = take_length()
        value_length = take_length()
        end = offset + name_length + value_length
        if end > len(data):
            raise ValueError("truncated FastCGI params")
        name = data[offset:offset + name_length].decode("latin-1", "replace")
        offset += name_length
        result[name] = data[offset:offset + value_length]
        offset += value_length
    return result


def fcgi_record(record_type, request_id, content=b""):
    if len(content) > 0xFFFF:
        raise ValueError("FastCGI record too large")
    return bytes((1, record_type, request_id >> 8, request_id & 0xFF,
                  len(content) >> 8, len(content) & 0xFF, 0, 0)) + content


def _fcgi_respond(sock, request_id, mode, body, keep_connection):
    data, partial, close_early, _upgrade = response_plan(
        mode, http=False, echo=body
    )
    wire = fcgi_record(6, request_id, data)
    if not close_early:
        wire += fcgi_record(6, request_id)
        wire += fcgi_record(3, request_id, b"\0" * 8)
    _send(sock, wire, partial)
    return close_early or not keep_connection


def handle_fastcgi(sock, max_request=_MAX_REQUEST):
    requests = {}
    while True:
        header = _recv_exact(sock, 8)
        version, record_type = header[0], header[1]
        request_id = int.from_bytes(header[2:4], "big")
        content_length = int.from_bytes(header[4:6], "big")
        padding_length = header[6]
        if version != 1 or request_id == 0:
            raise ValueError("invalid FastCGI record")
        content = _recv_exact(sock, content_length) if content_length else b""
        if padding_length:
            _recv_exact(sock, padding_length)

        if record_type == 1:
            if len(content) != 8 or request_id in requests:
                raise ValueError("invalid FastCGI begin request")
            state = {"params": bytearray(), "body": bytearray(),
                     "headers": {}, "uri": b"/", "keep": False}
            requests[request_id] = state
            state["keep"] = bool(content[2] & 1)
            continue

        state = requests.get(request_id)
        if state is None:
            raise ValueError("FastCGI record without begin request")
        if record_type == 4:
            if content:
                if len(state["params"]) + len(content) > max_request:
                    raise ValueError("FastCGI params too large")
                state["params"].extend(content)
            else:
                params = _fcgi_params(state["params"])
                state["uri"] = params.get("REQUEST_URI", b"/")
                state["headers"] = {
                    key[5:].lower().replace("_", "-"): value
                    for key, value in params.items() if key.startswith("HTTP_")
                }
        elif record_type == 5:
            if content:
                if len(state["body"]) + len(content) > max_request:
                    raise ValueError("FastCGI body too large")
                state["body"].extend(content)
            else:
                mode = select_mode(state["uri"], state["headers"])
                close = _fcgi_respond(
                    sock, request_id, mode, bytes(state["body"]), state["keep"]
                )
                requests.pop(request_id, None)
                if close:
                    return True
        elif record_type == 2:
            requests.pop(request_id, None)


def _parse_scgi_headers(data):
    fields = data.split(b"\0")
    if fields and not fields[-1]:
        fields.pop()
    if len(fields) % 2:
        raise ValueError("invalid SCGI headers")
    result = {}
    for index in range(0, len(fields), 2):
        result[fields[index].decode("latin-1", "replace")] = fields[index + 1]
    return result


def handle_scgi(sock, max_request=_MAX_REQUEST):
    digits = bytearray()
    while len(digits) < 10:
        char = _recv_exact(sock, 1)
        if char == b":":
            break
        if not char.isdigit():
            raise ValueError("invalid SCGI netstring")
        digits.extend(char)
    else:
        raise ValueError("SCGI length is too long")
    if not digits:
        raise ValueError("missing SCGI length")
    header_length = int(digits)
    if header_length <= 0 or header_length > _MAX_HEADERS:
        raise ValueError("invalid SCGI header length")
    headers = _parse_scgi_headers(_recv_exact(sock, header_length))
    if _recv_exact(sock, 1) != b",":
        raise ValueError("invalid SCGI netstring terminator")
    try:
        content_length = int(headers.get("CONTENT_LENGTH", b"0"))
    except (TypeError, ValueError):
        raise ValueError("invalid SCGI content length") from None
    if content_length < 0 or content_length > max_request:
        raise ValueError("invalid SCGI content length")
    body = _recv_exact(sock, content_length) if content_length else b""
    request_headers = {
        key[5:].lower().replace("_", "-"): value
        for key, value in headers.items() if key.startswith("HTTP_")
    }
    mode = select_mode(headers.get("REQUEST_URI", b"/"), request_headers)
    data, partial, _close_early, _upgrade = response_plan(
        mode, http=False, echo=body
    )
    _send(sock, data, partial)
    return True


_HANDLERS = {"http": handle_http, "fastcgi": handle_fastcgi, "scgi": handle_scgi}


class BackendServer:
    """Bounded-worker loopback TCP server for one backend protocol."""

    def __init__(self, protocol, port, workers=16, timeout=5.0,
                 max_request=_MAX_REQUEST):
        if protocol not in _HANDLERS:
            raise ValueError(f"unsupported protocol: {protocol}")
        self.protocol = protocol
        self.requested_port = port
        self.workers = workers
        self.timeout = timeout
        self.max_request = max_request
        self.port = None
        self._listener = None
        self._stopping = threading.Event()
        self._queue = queue.Queue(maxsize=max(4, workers * 4))
        self._threads = []
        self._active = set()
        self._active_lock = threading.Lock()

    def start(self):
        if self._listener is not None:
            return self
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind(("127.0.0.1", self.requested_port))
            listener.listen(128)
            listener.settimeout(0.2)
        except Exception:
            listener.close()
            raise
        self._listener = listener
        self.port = listener.getsockname()[1]
        for number in range(self.workers):
            thread = threading.Thread(
                target=self._worker, name=f"{self.protocol}-backend-{number}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)
        acceptor = threading.Thread(
            target=self._accept, name=f"{self.protocol}-backend-accept", daemon=True
        )
        acceptor.start()
        self._threads.append(acceptor)
        return self

    def _accept(self):
        listener = self._listener
        while not self._stopping.is_set():
            try:
                client, _address = listener.accept()
                client.settimeout(self.timeout)
                try:
                    self._queue.put_nowait(client)
                except queue.Full:
                    client.close()
            except socket.timeout:
                continue
            except OSError:
                break

    def _worker(self):
        handler = _HANDLERS[self.protocol]
        while not self._stopping.is_set():
            try:
                client = self._queue.get(timeout=0.2)
            except queue.Empty:
                continue
            with self._active_lock:
                self._active.add(client)
            try:
                with client:
                    handler(client, self.max_request)
            # An individual malformed request must not terminate a worker.
            except Exception:
                pass
            finally:
                with self._active_lock:
                    self._active.discard(client)
                self._queue.task_done()

    def stop(self):
        self._stopping.set()
        listener, self._listener = self._listener, None
        if listener is not None:
            listener.close()
        with self._active_lock:
            for client in tuple(self._active):
                try:
                    client.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                client.close()
        while True:
            try:
                client = self._queue.get_nowait()
            except queue.Empty:
                break
            client.close()
            self._queue.task_done()
        for thread in self._threads:
            thread.join(timeout=1)
        self._threads.clear()

    def __enter__(self):
        return self.start()

    def __exit__(self, _type, _value, _traceback):
        self.stop()


def _port(value):
    port = int(value)
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535")
    return port


def _write_ready(path, servers):
    path = Path(path)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    payload = "".join(f"{server.protocol}={server.port}\n" for server in servers)
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as output:
            output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        os.link(temporary, path)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def main(argv=None):
    modes = ", ".join(MODE_NAMES)
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(f"The final path component selects the response, for example "
                f"/backend/MODE, /fcgi/MODE, /fastcgi/MODE, /scgi/MODE, "
                f"/h2-proxy/MODE, /h2-fastcgi/MODE, or /h2-scgi/MODE. "
                f"Modes: {modes}"),
    )
    parser.add_argument("--http-port", type=_port, default=5701)
    parser.add_argument("--fastcgi-port", type=_port, default=5702)
    parser.add_argument("--scgi-port", type=_port, default=5703)
    parser.add_argument("--workers", type=int, default=16)
    parser.add_argument("--timeout", type=float, default=5.0)
    parser.add_argument("--ready-file", type=Path)
    args = parser.parse_args(argv)
    if args.workers < 1 or args.workers > 128:
        parser.error("--workers must be between 1 and 128")
    if args.timeout <= 0 or args.timeout > 300:
        parser.error("--timeout must be greater than 0 and at most 300")

    servers = [
        BackendServer("http", args.http_port, args.workers, args.timeout),
        BackendServer("fastcgi", args.fastcgi_port, args.workers, args.timeout),
        BackendServer("scgi", args.scgi_port, args.workers, args.timeout),
    ]
    stopping = threading.Event()

    def request_stop(_signum, _frame):
        stopping.set()

    old_handlers = {}
    for signum in (signal.SIGINT, signal.SIGTERM):
        old_handlers[signum] = signal.signal(signum, request_stop)

    ready_created = False
    try:
        for server in servers:
            server.start()
        if args.ready_file:
            _write_ready(args.ready_file, servers)
            ready_created = True
        ports = " ".join(f"{server.protocol}=127.0.0.1:{server.port}"
                         for server in servers)
        print(f"backend responder ready: {ports}", flush=True)
        stopping.wait()
    finally:
        for server in reversed(servers):
            server.stop()
        if ready_created:
            try:
                args.ready_file.unlink()
            except FileNotFoundError:
                pass
        for signum, handler in old_handlers.items():
            signal.signal(signum, handler)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(130)
    except Exception as error:
        print(f"backend-responder: {error}", file=sys.stderr)
        raise SystemExit(1)
