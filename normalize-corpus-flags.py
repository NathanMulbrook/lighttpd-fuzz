#!/usr/bin/env python3

"""Prepare an HTTP corpus for the flag-based multipacket fuzzer."""

import hashlib
import os
import sys
from pathlib import Path


GET_ROOT = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
GET_KEEPALIVE = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n"
GET_FILE = (
    b"GET /files/index.txt HTTP/1.1\r\n"
    b"Host: localhost\r\nAccept-Encoding: gzip\r\nConnection: close\r\n\r\n"
)
OPTIONS = b"OPTIONS * HTTP/1.1\r\nHost: localhost\r\n\r\n"
HEAD_ROOT = b"HEAD / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
RANGE_REQUEST = (
    b"GET /files/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Range: bytes=0-7\r\nConnection: close\r\n\r\n"
)
FORWARDED_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: localhost\r\n"
    b"Forwarded: for=192.0.2.1;proto=https\r\nConnection: close\r\n\r\n"
)
PRIVATE_REQUEST = (
    b"GET /private/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
PRIVATE_AUTH_REQUEST = (
    b"GET /private/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Authorization: Basic ZnV6ejpmdXp6\r\nConnection: close\r\n\r\n"
)
STATUS_REQUEST = (
    b"GET /server-status?auto HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
ALIAS_REQUEST = (
    b"GET /alias/index.txt HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)
REDIRECT_REQUEST = (
    b"GET /redirect HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)
REWRITE_REQUEST = (
    b"GET /rewrite/files/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
WEBDAV_PUT = (
    b"PUT /dav/seed.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 4\r\n\r\nseed"
)
WEBDAV_CHUNKED_PUT = (
    b"PUT /dav/chunked.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
    b"4\r\nseed\r\n0\r\n\r\n"
)
H2C_UPGRADE = (
    b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: Upgrade, HTTP2-Settings\r\n"
    b"Upgrade: h2c\r\nHTTP2-Settings: AAMAAABkAAQAAP__\r\n\r\n"
)
HTTP10_RANGE = (
    b"GET /files/large.txt HTTP/1.0\r\nRange: bytes=0-15\r\n"
    b"Connection: close\r\n\r\n"
)
MULTI_RANGE = (
    b"GET /files/large.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Range: bytes=96-127,0-15,8-31,-16\r\nConnection: close\r\n\r\n"
)
UNSATISFIABLE_RANGE = (
    b"GET /files/large.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Range: bytes=999999-1000000\r\nConnection: close\r\n\r\n"
)
IF_RANGE = (
    b"GET /files/large.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Range: bytes=0-31\r\nIf-Range: \"stale-seed-etag\"\r\n"
    b"Connection: close\r\n\r\n"
)
CONDITIONAL_GET = (
    b"GET /files/large.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"If-None-Match: *\r\n"
    b"If-Modified-Since: Sun, 06 Nov 2094 08:49:37 GMT\r\n"
    b"Connection: close\r\n\r\n"
)
ABSOLUTE_URI = (
    b"GET http://localhost/files/index.txt?absolute=1 HTTP/1.1\r\n"
    b"Connection: close\r\n\r\n"
)
DIRLIST_HTML = (
    b"GET /listing/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)
DIRLIST_JSON = (
    b"GET /listing/?json HTTP/1.1\r\nHost: localhost\r\n"
    b"Accept: application/json\r\nConnection: close\r\n\r\n"
)
CONDITIONS_REQUEST = (
    b"POST /branch/conditions/target?mode=fuzz HTTP/1.1\r\n"
    b"Host: conditions.example\r\nUser-Agent: FuzzAgent\r\n"
    b"Referer: http://trusted.example/seed\r\nCookie: fuzz=yes\r\n"
    b"Accept-Language: en-US\r\nContent-Length: 4\r\n"
    b"Connection: close\r\n\r\nseed"
)
VHOST_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: one.example\r\nConnection: close\r\n\r\n"
)
VHOST_FALLBACK_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: missing.example\r\nConnection: close\r\n\r\n"
)
EVHOST_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: www.example.org\r\nConnection: close\r\n\r\n"
)
USERDIR_REQUEST = (
    b"GET /~fuzz/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)
SSI_REQUEST = (
    b"GET /ssi/index.shtml?seed=yes HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
CGI_GET = (
    b"GET /cgi/echo.cgi?normal HTTP/1.1\r\nHost: localhost\r\n"
    b"X-Fuzz: seed\r\nConnection: close\r\n\r\n"
)
CGI_STATUS = (
    b"GET /cgi/echo.cgi?status HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
CGI_REDIRECT = (
    b"GET /cgi/echo.cgi?redirect HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
CGI_XSENDFILE = (
    b"GET /cgi/echo.cgi?xsendfile HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
CGI_STREAM = (
    b"GET /cgi/echo.cgi?stream HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
CGI_POST = (
    b"POST /cgi/echo.cgi?normal HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Type: application/octet-stream\r\nContent-Length: 4\r\n"
    b"Connection: close\r\n\r\nseed"
)
CGI_EXPECT_HEADERS = (
    b"POST /cgi/echo.cgi?normal HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Type: application/octet-stream\r\nContent-Length: 4\r\n"
    b"Expect: 100-continue\r\nConnection: close\r\n\r\n"
)
CGI_CHUNKED_TRAILER = (
    b"POST /cgi/echo.cgi?stream HTTP/1.1\r\nHost: localhost\r\n"
    b"Transfer-Encoding: chunked\r\nTrailer: Test-Trailer\r\n"
    b"Connection: close\r\n\r\n4\r\nseed\r\n0\r\n"
    b"Test-Trailer: finished\r\n\r\n"
)
INVALID_TRANSFER_LENGTH = (
    b"POST /cgi/echo.cgi HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n"
    b"4\r\nseed\r\n0\r\n\r\n"
)
DIGEST_CHALLENGE_REQUEST = (
    b"GET /digest/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
DIGEST_AUTH_REQUEST = (
    b"GET /digest/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Authorization: Digest username=\"fuzz\", realm=\"lighttpd-fuzz-digest\", "
    b"nonce=\"seed\", uri=\"/digest/index.txt\", algorithm=MD5, "
    b"response=\"00000000000000000000000000000000\", qop=auth, "
    b"nc=00000001, cnonce=\"seed\"\r\nConnection: close\r\n\r\n"
)
BASIC_USER_AUTH_REQUEST = (
    b"GET /basic-user/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Authorization: Basic ZnV6ejpmdXp6\r\nConnection: close\r\n\r\n"
)
INVALID_BASIC_AUTH_REQUEST = (
    b"GET /private/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Authorization: Basic !!!not-base64!!!\r\nConnection: close\r\n\r\n"
)


def encoded_request(path, extra_headers=b""):
    return (
        b"GET " + path + b" HTTP/1.1\r\nHost: localhost\r\n" + extra_headers
        + b"Connection: close\r\n\r\n"
    )


CONDITION_ROUTING_REQUESTS = (
    encoded_request(b"/condition-alias/index.txt"),
    encoded_request(b"/condition-redirect/files/index.txt"),
    encoded_request(b"/condition-rewrite/files/index.txt"),
    encoded_request(b"/anything.deny"),
    b"GET /missing HTTP/1.1\r\nHost: status-errors.example\r\n"
    b"Connection: close\r\n\r\n",
)
URL_NORMALIZATION_REQUESTS = (
    encoded_request(b"/files/%69ndex.txt?space=a%20b+c"),
    encoded_request(b"/files%2findex.txt"),
    encoded_request(b"/files/./../files/index.txt"),
    encoded_request(b"/files\\index.txt"),
    encoded_request(b"/files/%ff.txt"),
)
STATIC_PROFILE_REQUESTS = (
    encoded_request(b"/static/no-etag/large.txt", b"If-None-Match: *\r\n"),
    encoded_request(b"/static/pathinfo/large.txt/extra"),
    encoded_request(b"/static/index/"),
    encoded_request(b"/static/link.txt"),
    encoded_request(b"/no-etag/large.txt", b"If-None-Match: *\r\n"),
    encoded_request(b"/indexes/"),
    encoded_request(b"/no-follow/link.txt"),
)
USERDIR_EDGE_REQUESTS = tuple(
    encoded_request(path)
    for path in (b"/~./", b"/~../", b"/~root/", b"/~fuzz", b"/~fuzz/%2e%2e/")
)
DEFLATE_REQUESTS = tuple(
    encoded_request(
        b"/files/large.txt", b"Accept-Encoding: " + encoding + b"\r\n"
    )
    for encoding in (
        b"zstd",
        b"br",
        b"gzip",
        b"deflate",
        b"bzip2",
        b"gzip;q=0.3, br;q=1.0, zstd;q=0.7, identity;q=0.1",
    )
)
WEBDAV_OPTIONS = (
    b"OPTIONS /dav/ HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)
WEBDAV_PROPFIND = (
    b"PROPFIND /dav/ HTTP/1.1\r\nHost: localhost\r\nDepth: 1\r\n"
    b"Content-Type: application/xml\r\nContent-Length: 82\r\n"
    b"Connection: close\r\n\r\n"
    b"<?xml version=\"1.0\"?><propfind xmlns=\"DAV:\"><prop>"
    b"<displayname/></prop></propfind>"
)
WEBDAV_PROPFIND_INFINITY = (
    b"PROPFIND /dav/ HTTP/1.1\r\nHost: localhost\r\nDepth: infinity\r\n"
    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
)
WEBDAV_MKCOL = (
    b"MKCOL /dav/seed-collection HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 0\r\nConnection: close\r\n\r\n"
)
WEBDAV_COPY = (
    b"COPY /dav/seed.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Destination: /dav/copied.txt\r\nOverwrite: T\r\nDepth: infinity\r\n"
    b"Connection: close\r\n\r\n"
)
WEBDAV_MOVE = (
    b"MOVE /dav/copied.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Destination: /dav/moved.txt\r\nOverwrite: F\r\n"
    b"Connection: close\r\n\r\n"
)
WEBDAV_DELETE = (
    b"DELETE /dav/moved.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
WEBDAV_PARTIAL_PUT = (
    b"PUT /dav/seed.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Range: bytes 1-2/*\r\nContent-Length: 2\r\n"
    b"Connection: close\r\n\r\nXX"
)
MISSING_REQUEST = (
    b"GET /missing HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
)
MALFORMED_HOST_REQUEST = (
    b"GET / HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n"
)
MISSING_HOST_REQUEST = b"GET / HTTP/1.1\r\nConnection: close\r\n\r\n"
OVERSIZED_REQUEST_FIELD = (
    b"GET / HTTP/1.1\r\nHost: localhost\r\nX-Oversized: "
    + (b"A" * 1100)
    + b"\r\nConnection: close\r\n\r\n"
)
GET_WITH_BODY = (
    b"GET /cgi/echo.cgi?normal HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 4\r\nConnection: close\r\n\r\nseed"
)
STATUS_STATISTICS_REQUEST = (
    b"GET /server-statistics HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n"
)
WEBSOCKET_UPGRADE = (
    b"GET /ws/ HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
    b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n"
)
WSTUNNEL_UPGRADE = (
    b"GET /ws/ HTTP/1.1\r\nHost: localhost\r\nUpgrade: websocket\r\n"
    b"Connection: Upgrade\r\nSec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n"
    b"Origin: http://localhost\r\n\r\n"
)
CONNECT_REQUEST = (
    b"CONNECT :5602 HTTP/1.1\r\nHost: localhost\r\n\r\n"
)
HAPROXY_V1_GET = (
    b"PROXY TCP4 192.0.2.1 127.0.0.1 12345 80\r\n" + GET_ROOT
)
HAPROXY_V1_UNKNOWN = b"PROXY UNKNOWN\r\n" + GET_ROOT
HAPROXY_V2_GET = (
    bytes.fromhex("0d0a0d0a000d0a515549540a2111000c")
    + bytes((192, 0, 2, 1, 127, 0, 0, 1))
    + (12345).to_bytes(2, "big")
    + (80).to_bytes(2, "big")
    + GET_ROOT
)
_HAPROXY_V2_ADDRESS = (
    bytes((192, 0, 2, 1, 127, 0, 0, 1))
    + (12345).to_bytes(2, "big")
    + (80).to_bytes(2, "big")
)
_HAPROXY_V2_SSL = (
    b"\x01"
    + (0).to_bytes(4, "big")
    + b"\x21\x00\x07TLSv1.3"
)
_HAPROXY_V2_TLVS = (
    b"\x01\x00\x02h2"
    + b"\x02\x00\x0bone.example"
    + b"\x05\x00\x04seed"
    + b"\x20"
    + len(_HAPROXY_V2_SSL).to_bytes(2, "big")
    + _HAPROXY_V2_SSL
)
HAPROXY_V2_TLV_GET = (
    bytes.fromhex("0d0a0d0a000d0a515549540a")
    + b"\x21\x11"
    + (len(_HAPROXY_V2_ADDRESS) + len(_HAPROXY_V2_TLVS)).to_bytes(2, "big")
    + _HAPROXY_V2_ADDRESS
    + _HAPROXY_V2_TLVS
    + b"GET /files/index.txt HTTP/1.1\r\nHost: original.example\r\n"
    + b"Connection: close\r\n\r\n"
)
PROXY_REQUESTS = (
    b"GET /proxy/files/index.txt HTTP/1.1\r\nHost: proxy.example\r\n"
    b"Forwarded: for=192.0.2.60;proto=https\r\nConnection: close\r\n\r\n",
    b"POST /proxy/cgi/echo.cgi?normal HTTP/1.1\r\nHost: proxy.example\r\n"
    b"Content-Length: 4\r\nConnection: close\r\n\r\nseed",
    b"GET /gateway/files/index.txt HTTP/1.1\r\nHost: gateway.example\r\n"
    b"Connection: close\r\n\r\n",
    b"GET /gateway/ws/ HTTP/1.1\r\nHost: gateway.example\r\n"
    b"Connection: Upgrade\r\nUpgrade: websocket\r\n"
    b"Sec-WebSocket-Version: 13\r\n"
    b"Sec-WebSocket-Key: MDEyMzQ1Njc4OWFiY2RlZg==\r\n\r\n",
)
BACKEND_RESPONSE_MODES = (
    b"normal",
    b"chunked-trailers",
    b"100",
    b"103",
    b"interim",
    b"early-close",
    b"malformed-headers",
    b"truncated-headers",
    b"malformed-chunk",
    b"truncated-chunk",
    b"redirect-cookie",
    b"upgrade",
    b"partial",
)
BACKEND_PROXY_REQUESTS = tuple(
    encoded_request(b"/proxy/" + mode, b"X-Backend-Seed: proxy\r\n")
    for mode in BACKEND_RESPONSE_MODES
)
BACKEND_GATEWAY_REQUESTS = tuple(
    encoded_request(b"/gateway/" + mode, b"X-Backend-Seed: gateway\r\n")
    for mode in BACKEND_RESPONSE_MODES
)
LEGACY_PROXY_REQUESTS = tuple(
    b"GET /legacy-proxy/" + mode + b" HTTP/1.1\r\n"
    b"Host: legacy.example\r\n"
    b"Forwarded: for=192.0.2.44;proto=https\r\n"
    b"Connection: close\r\n\r\n"
    for mode in BACKEND_RESPONSE_MODES
)
BACKEND_FASTCGI_REQUESTS = tuple(
    encoded_request(b"/fastcgi/" + mode, b"X-Backend-Seed: fastcgi\r\n")
    for mode in BACKEND_RESPONSE_MODES
)
BACKEND_SCGI_REQUESTS = tuple(
    encoded_request(b"/scgi/" + mode, b"X-Backend-Seed: scgi\r\n")
    for mode in BACKEND_RESPONSE_MODES
)
BACKEND_FASTCGI_POST_HEADERS = (
    b"POST /fastcgi/normal HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Type: application/octet-stream\r\nContent-Length: 4\r\n"
    b"Connection: close\r\n\r\n"
)
BACKEND_SCGI_POST_HEADERS = (
    b"POST /scgi/normal HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Type: application/octet-stream\r\nContent-Length: 4\r\n"
    b"Connection: close\r\n\r\n"
)
BACKEND_UPGRADE_REQUEST = (
    b"GET /proxy/upgrade HTTP/1.1\r\nHost: proxy.example\r\n"
    b"Connection: Upgrade\r\nUpgrade: backend-echo\r\n\r\n"
)
BACKEND_GATEWAY_UPGRADE_REQUEST = (
    b"GET /gateway/upgrade HTTP/1.1\r\nHost: gateway.example\r\n"
    b"Connection: Upgrade\r\nUpgrade: backend-echo\r\n\r\n"
)


def websocket_client_frame(payload, opcode=2):
    if len(payload) > 125:
        raise ValueError("seed websocket payload is too large")
    mask = b"\x11\x22\x33\x44"
    masked = bytes(byte ^ mask[index & 3] for index, byte in enumerate(payload))
    return bytes((0x80 | opcode, 0x80 | len(payload))) + mask + masked


WSTUNNEL_BACKEND_REQUEST = (
    b"GET /normal HTTP/1.1\r\nHost: websocket-backend\r\n"
    b"Connection: close\r\n\r\n"
)
WSTUNNEL_BACKEND_FRAME = websocket_client_frame(WSTUNNEL_BACKEND_REQUEST)
BACKEND_CONNECT_TUNNEL_REQUESTS = (
    b"CONNECT :6501 HTTP/1.1\r\nHost: localhost\r\n\r\n",
    b"GET /normal HTTP/1.1\r\nHost: tunneled.example\r\nConnection: close\r\n\r\n",
)
FORWARDED_CHAIN_REQUESTS = (
    b"GET / HTTP/1.1\r\nHost: original.example\r\n"
    b"Forwarded: for=192.0.2.10;proto=https;host=forwarded.example, "
    b"for=198.51.100.7\r\nConnection: close\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: localhost\r\n"
    b"X-Forwarded-For: 192.0.2.1, 198.51.100.2\r\n"
    b"X-Real-IP: 203.0.113.9\r\nConnection: close\r\n\r\n",
)
FORWARDED_IPV6_REQUEST = (
    b"GET /files/index.txt HTTP/1.1\r\nHost: original.example\r\n"
    b"Forwarded: for=\"[2001:db8::1]:1234\";by=_edge;proto=https;"
    b"host=\"one.example:443\";remote_user=\"fuzz user\"\r\n"
    b"Connection: close\r\n\r\n"
)
HAPROXY_V1_TCP6_FORWARDED = (
    b"PROXY TCP6 2001:db8::10 2001:db8::20 12345 80\r\n"
    + FORWARDED_IPV6_REQUEST
)
ACCESSLOG_FIELDS_REQUEST = (
    b"GET /files/index.txt?access=log HTTP/1.1\r\nHost: access.example\r\n"
    b"User-Agent: FuzzAgent/1.0 \xe2\x98\x83\r\n"
    b"Cookie: fuzz=a%20b; other=\"quoted\"\r\n"
    b"Connection: keep-alive\r\n\r\n"
)
ADMIN_REQUESTS = tuple(
    encoded_request(path)
    for path in (
        b"/admin/server-status?auto",
        b"/admin/server-config",
        b"/admin/server-statistics",
    )
)
STATUS_VARIANT_REQUESTS = tuple(
    encoded_request(path)
    for path in (
        b"/server-status?json",
        b"/server-status?jsonp=Fuzz_cb",
        b"/server-status?jsonp=1bad",
        b"/admin/server-status?json",
        b"/admin/server-status?jsonp=Fuzz_cb",
    )
)
STACK_REQUESTS = (
    encoded_request(b"/stack-alias/index.txt"),
    encoded_request(b"/stack-redirect"),
    encoded_request(b"/stack-rewrite/files/index.txt"),
    encoded_request(b"/ssi/raw.ssi"),
)
SSI_EDGE_REQUESTS = (
    encoded_request(b"/ssi/index.shtml"),
    b"HEAD /ssi/index.shtml HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n",
    encoded_request(b"/ssi/include.shtml"),
    encoded_request(b"/ssi/nested.shtml"),
)
SSI_EXEC_REQUEST = encoded_request(b"/ssi/exec.shtml")
ROUTING_INTERACTION_REQUESTS = (
    b"GET /route-alias/index.txt HTTP/1.1\r\nHost: routes.example\r\n"
    b"Connection: close\r\n\r\n",
    b"GET /route-rewrite/index.txt HTTP/1.1\r\nHost: routes.example\r\n"
    b"Connection: close\r\n\r\n",
    b"GET /route-redirect HTTP/1.1\r\nHost: routes.example\r\n"
    b"Connection: close\r\n\r\n",
    b"GET /~fuzz/ HTTP/1.1\r\nHost: routes.example\r\n"
    b"Connection: close\r\n\r\n",
)


def _base36_pair(value):
    alphabet = b"0123456789abcdefghijklmnopqrstuvwxyz"
    return bytes((alphabet[value // 36], alphabet[value % 36]))


CGI_DENSE_HEADERS = (
    b"GET /cgi/echo.cgi?normal HTTP/1.1\r\nHost: localhost\r\n"
    + b"".join(b"X" + _base36_pair(i) + b":a\r\n" for i in range(1050))
    + b"Connection: close\r\n\r\n"
)

CHUNKED_EXTENSION_REQUEST = (
    b"POST /cgi/echo.cgi?normal HTTP/1.1\r\nHost: localhost\r\n"
    b"Transfer-Encoding: chunked\r\nTrailer: Test-Trailer\r\n"
    b"Connection: close\r\n\r\n"
    b"4;name=value\r\nseed\r\n3;quoted=\"yes\"\r\nxyz\r\n0\r\n"
    b"Test-Trailer: finished\r\n\r\n"
)
CHUNKED_FRAGMENT_PACKETS = (
    b"POST /cgi/echo.cgi?normal HTTP/1.1\r\nHost: localhost\r\n"
    b"Transfer-Encoding: chunked\r\nTrailer: Test-Trailer\r\n"
    b"Connection: close\r\n\r\n4;fragment=yes\r",
    b"\nse",
    b"ed\r",
    b"\n0\r\nTest-Trailer: finished\r\n",
    b"\r\n",
)

WEBDAV_LIFECYCLE_REQUESTS = (
    b"MKCOL /dav/corpus-chain HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    b"PUT /dav/corpus-chain/source.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 16\r\nConnection: keep-alive\r\n\r\ncoverage-seed-01",
    b"COPY /dav/corpus-chain/source.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Destination: /dav/corpus-chain/copied.txt\r\nOverwrite: T\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"PROPFIND /dav/corpus-chain/copied.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Depth: 0\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    b"MOVE /dav/corpus-chain/copied.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Destination: /dav/corpus-chain/moved.txt\r\nOverwrite: T\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"DELETE /dav/corpus-chain/source.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"DELETE /dav/corpus-chain/moved.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"DELETE /dav/corpus-chain HTTP/1.1\r\nHost: localhost\r\n"
    b"Depth: infinity\r\nConnection: close\r\n\r\n",
)

WEBDAV_TREE_REQUESTS = (
    b"MKCOL /dav/corpus-tree HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    b"MKCOL /dav/corpus-tree/child HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    b"PUT /dav/corpus-tree/child/item.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 9\r\nConnection: keep-alive\r\n\r\ntree-seed",
    b"COPY /dav/corpus-tree HTTP/1.1\r\nHost: localhost\r\n"
    b"Destination: /dav/corpus-tree-copy\r\nDepth: infinity\r\nOverwrite: T\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"PROPFIND /dav/corpus-tree-copy/ HTTP/1.1\r\nHost: localhost\r\n"
    b"Depth: infinity\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
    b"DELETE /dav/corpus-tree-copy HTTP/1.1\r\nHost: localhost\r\n"
    b"Depth: infinity\r\nConnection: keep-alive\r\n\r\n",
    b"DELETE /dav/corpus-tree HTTP/1.1\r\nHost: localhost\r\n"
    b"Depth: infinity\r\nConnection: close\r\n\r\n",
)

WEBDAV_PARTIAL_PUT_REQUESTS = (
    b"PUT /dav/corpus-partial.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Length: 6\r\nConnection: keep-alive\r\n\r\nabcdef",
    b"PUT /dav/corpus-partial.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Content-Range: bytes 1-2/*\r\nContent-Length: 2\r\n"
    b"Connection: keep-alive\r\n\r\nXY",
    b"GET /dav/corpus-partial.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"DELETE /dav/corpus-partial.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n",
)

CONNECT_TUNNEL_REQUESTS = (
    b"CONNECT localhost:5602 HTTP/1.1\r\nHost: localhost:5602\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"GET /files/index.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: close\r\n\r\n",
)

LISTING_CACHE_REQUESTS = (
    b"GET /listing/ HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"GET /listing/ HTTP/1.1\r\nHost: localhost\r\n"
    b"Connection: keep-alive\r\n\r\n",
    b"GET /listing/?json HTTP/1.1\r\nHost: localhost\r\n"
    b"Accept: application/json\r\nConnection: close\r\n\r\n",
)
DEFLATE_CACHE_REQUESTS = (
    b"GET /files/large.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Accept-Encoding: zstd\r\nConnection: keep-alive\r\n\r\n",
    b"GET /files/large.txt HTTP/1.1\r\nHost: localhost\r\n"
    b"Accept-Encoding: zstd\r\nConnection: close\r\n\r\n",
)


H2_CONNECTION_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def h2_frame(frame_type, flags, stream_id, payload=b""):
    if len(payload) > 0xFFFFFF:
        raise ValueError("HTTP/2 frame payload is too large")
    return (
        len(payload).to_bytes(3, "big")
        + bytes((frame_type, flags))
        + (stream_id & 0x7FFFFFFF).to_bytes(4, "big")
        + payload
    )


def hpack_integer(value, prefix_bits, first_byte=0):
    prefix_max = (1 << prefix_bits) - 1
    if value < prefix_max:
        return bytes((first_byte | value,))
    result = bytearray((first_byte | prefix_max,))
    value -= prefix_max
    while value >= 128:
        result.append((value & 0x7F) | 0x80)
        value >>= 7
    result.append(value)
    return bytes(result)


def hpack_raw_string(value):
    return hpack_integer(len(value), 7) + value


def hpack_literal(index, value):
    return hpack_integer(index, 4) + hpack_raw_string(value)


def hpack_literal_name(name, value):
    return b"\x00" + hpack_raw_string(name) + hpack_raw_string(value)


def h2_request_headers(method, path, end_stream=True, headers=(), stream_id=1):
    method_field = b"\x82" if method == b"GET" else hpack_literal(2, method)
    block = (
        method_field
        + b"\x86"
        + hpack_literal(4, path)
        + hpack_literal(1, b"localhost")
    )
    block += b"".join(hpack_literal_name(name, value) for name, value in headers)
    flags = 0x04 | (0x01 if end_stream else 0)
    return h2_frame(0x01, flags, stream_id, block)


H2_SETTINGS = h2_frame(0x04, 0, 0)
H2_PREFACE = H2_CONNECTION_PREFACE + H2_SETTINGS
H2_GET_ROOT = H2_PREFACE + h2_request_headers(b"GET", b"/")
H2_GET_STATUS = H2_PREFACE + h2_request_headers(b"GET", b"/server-status")
H2_CONTROL_FRAMES = (
    H2_PREFACE
    + h2_frame(0x04, 0, 0, b"\x00\x01\x00\x00\x00\x00")
    + h2_frame(0x06, 0, 0, b"fuzzping")
    + h2_frame(0x08, 0, 0, b"\x00\x00\x10\x00")
    + h2_request_headers(b"GET", b"/")
)
H2_PUT_HEADERS = h2_request_headers(b"PUT", b"/dav/h2.txt", end_stream=False)
H2_PUT = H2_PREFACE + H2_PUT_HEADERS + h2_frame(0x00, 0x01, 1, b"seed")
H2_GET_CGI = H2_PREFACE + h2_request_headers(
    b"GET", b"/cgi/echo.cgi?normal", headers=((b"accept-encoding", b"gzip"),)
)
H2_GET_PROXY = H2_PREFACE + h2_request_headers(b"GET", b"/h2-proxy/files/index.txt")
H2_GET_NORMALIZED = H2_PREFACE + h2_request_headers(b"GET", b"/files/%69ndex.txt")
H2_BACKEND_PROXY_REQUESTS = tuple(
    H2_PREFACE + h2_request_headers(b"GET", b"/h2-proxy/" + mode)
    for mode in BACKEND_RESPONSE_MODES
)
H2_BACKEND_FASTCGI_REQUESTS = tuple(
    H2_PREFACE + h2_request_headers(b"GET", b"/h2-fastcgi/" + mode)
    for mode in BACKEND_RESPONSE_MODES
)
H2_BACKEND_SCGI_REQUESTS = tuple(
    H2_PREFACE + h2_request_headers(b"GET", b"/h2-scgi/" + mode)
    for mode in BACKEND_RESPONSE_MODES
)
_h2_split_headers = h2_request_headers(b"GET", b"/listing/?json")[9:]
_h2_split_at = len(_h2_split_headers) // 2
H2_CONTINUATION = (
    H2_PREFACE
    + h2_frame(0x01, 0x01, 1, _h2_split_headers[:_h2_split_at])
    + h2_frame(0x09, 0x04, 1, _h2_split_headers[_h2_split_at:])
)
H2_LIFECYCLE_FRAMES = (
    H2_PREFACE
    + h2_frame(0x02, 0, 3, b"\x00\x00\x00\x00\x10")
    + h2_request_headers(b"GET", b"/", end_stream=False)
    + h2_frame(0x03, 0, 1, b"\x00\x00\x00\x08")
    + h2_frame(0x07, 0, 0, b"\x00\x00\x00\x01\x00\x00\x00\x00")
)
H2_MULTI_STREAM = (
    H2_PREFACE
    + h2_request_headers(b"GET", b"/files/index.txt", stream_id=1)
    + h2_request_headers(b"GET", b"/server-status?auto", stream_id=3)
    + h2_request_headers(b"HEAD", b"/listing/", stream_id=5)
)
H2_EXPECT_HEADERS = H2_PREFACE + h2_request_headers(
    b"POST",
    b"/cgi/echo.cgi?normal",
    end_stream=False,
    headers=((b"content-length", b"4"), (b"expect", b"100-continue")),
)
H2_EXPECT_DATA = h2_frame(0x00, 0x01, 1, b"seed")
H2_EXPECT_CONTINUE = H2_EXPECT_HEADERS + H2_EXPECT_DATA
H2_REQUEST_TRAILERS = (
    H2_PREFACE
    + h2_request_headers(
        b"POST",
        b"/cgi/echo.cgi?stream",
        end_stream=False,
        headers=((b"te", b"trailers"),),
    )
    + h2_frame(0x00, 0, 1, b"seed")
    + h2_frame(
        0x01,
        0x05,
        1,
        hpack_literal_name(b"test-trailer", b"finished"),
    )
)
H2_PADDED_DATA = (
    H2_PREFACE
    + h2_request_headers(
        b"POST",
        b"/cgi/echo.cgi?normal",
        end_stream=False,
        headers=((b"content-length", b"4"),),
    )
    + h2_frame(0x00, 0x09, 1, b"\x02seed\x00\x00")
)


def h2_extended_connect_headers(path=b"/h2-ws/", stream_id=1):
    block = (
        hpack_literal(2, b"CONNECT")
        + b"\x86"
        + hpack_literal(4, path)
        + hpack_literal(1, b"localhost")
        + hpack_literal_name(b":protocol", b"websocket")
        + hpack_literal_name(b"sec-websocket-version", b"13")
        + hpack_literal_name(b"origin", b"http://localhost")
    )
    return h2_frame(0x01, 0x04, stream_id, block)


H2_WSTUNNEL_HEADERS = H2_PREFACE + h2_extended_connect_headers()
H2_WSTUNNEL_DATA = h2_frame(0x00, 0, 1, WSTUNNEL_BACKEND_FRAME)
H2_WSTUNNEL_REQUEST = H2_WSTUNNEL_HEADERS + H2_WSTUNNEL_DATA
H2_AUTH_WEBDAV_PUT = (
    H2_PREFACE
    + h2_request_headers(
        b"PUT",
        b"/dav/h2-auth.txt",
        end_stream=False,
        headers=(
            (b"authorization", b"Basic ZnV6ejpmdXp6"),
            (b"content-length", b"4"),
        ),
    )
    + h2_frame(0x00, 0x01, 1, b"seed")
)
H2_STATIC_CACHE_REQUESTS = (
    H2_PREFACE
    + h2_request_headers(
        b"GET",
        b"/files/large.txt",
        headers=((b"range", b"bytes=0-31"), (b"accept-encoding", b"gzip")),
    ),
    H2_PREFACE
    + h2_request_headers(
        b"GET",
        b"/files/large.txt",
        headers=((b"if-none-match", b"*"),),
    ),
    H2_PREFACE + h2_request_headers(b"GET", b"/listing/?json"),
)


def valid_multipacket(data):
    offset = 0
    packet_count = 0
    while offset < len(data):
        if len(data) - offset < 2:
            return False
        size = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        if size == 0 or size > len(data) - offset:
            return False
        offset += size
        packet_count += 1
        if packet_count > 64:
            return False
    return packet_count > 0


def multipacket(flags, packets):
    result = bytearray([flags])
    for packet in packets:
        result.extend(len(packet).to_bytes(2, "big"))
        result.extend(packet)
    return bytes(result)


def seed_inputs():
    seeds = [
        b"\x00" + GET_ROOT,
        b"\x01" + GET_ROOT,
        b"\x00" + GET_FILE,
        b"\x00" + OPTIONS,
        b"\x00" + HEAD_ROOT,
        b"\x00" + RANGE_REQUEST,
        b"\x00" + FORWARDED_REQUEST,
        b"\x00" + PRIVATE_REQUEST,
        b"\x00" + PRIVATE_AUTH_REQUEST,
        b"\x00" + STATUS_REQUEST,
        b"\x00" + ALIAS_REQUEST,
        b"\x00" + REDIRECT_REQUEST,
        b"\x00" + REWRITE_REQUEST,
        b"\x00" + WEBDAV_PUT,
        b"\x01" + WEBDAV_CHUNKED_PUT,
        b"\x00" + H2_PREFACE,
        b"\x00" + H2C_UPGRADE,
        b"\x00" + HTTP10_RANGE,
        b"\x00" + MULTI_RANGE,
        b"\x00" + UNSATISFIABLE_RANGE,
        b"\x00" + IF_RANGE,
        b"\x00" + CONDITIONAL_GET,
        b"\x00" + ABSOLUTE_URI,
        b"\x00" + DIRLIST_HTML,
        b"\x00" + DIRLIST_JSON,
        b"\x00" + CONDITIONS_REQUEST,
        b"\x00" + VHOST_REQUEST,
        b"\x00" + VHOST_FALLBACK_REQUEST,
        b"\x00" + EVHOST_REQUEST,
        b"\x00" + USERDIR_REQUEST,
        b"\x00" + SSI_REQUEST,
        b"\x00" + CGI_GET,
        b"\x00" + CGI_STATUS,
        b"\x00" + CGI_REDIRECT,
        b"\x00" + CGI_XSENDFILE,
        b"\x00" + CGI_STREAM,
        b"\x00" + CGI_POST,
        b"\x00" + CGI_CHUNKED_TRAILER,
        b"\x00" + INVALID_TRANSFER_LENGTH,
        b"\x00" + DIGEST_CHALLENGE_REQUEST,
        b"\x00" + DIGEST_AUTH_REQUEST,
        b"\x00" + BASIC_USER_AUTH_REQUEST,
        b"\x00" + INVALID_BASIC_AUTH_REQUEST,
        b"\x00" + WEBDAV_OPTIONS,
        b"\x00" + WEBDAV_PROPFIND,
        b"\x00" + WEBDAV_PROPFIND_INFINITY,
        b"\x00" + WEBDAV_MKCOL,
        b"\x00" + WEBDAV_COPY,
        b"\x00" + WEBDAV_MOVE,
        b"\x00" + WEBDAV_DELETE,
        b"\x00" + WEBDAV_PARTIAL_PUT,
        b"\x00" + MISSING_REQUEST,
        b"\x00" + MALFORMED_HOST_REQUEST,
        b"\x00" + MISSING_HOST_REQUEST,
        b"\x00" + OVERSIZED_REQUEST_FIELD,
        b"\x00" + GET_WITH_BODY,
        b"\x00" + STATUS_STATISTICS_REQUEST,
        b"\x00" + WEBSOCKET_UPGRADE,
        b"\x00" + WSTUNNEL_UPGRADE,
        b"\x00" + CONNECT_REQUEST,
        b"\x00" + HAPROXY_V1_GET,
        b"\x00" + HAPROXY_V1_UNKNOWN,
        b"\x00" + HAPROXY_V2_GET,
        b"\x00" + HAPROXY_V2_TLV_GET,
        b"\x00" + HAPROXY_V1_TCP6_FORWARDED,
        b"\x00" + H2_GET_ROOT,
        b"\x00" + H2_GET_STATUS,
        b"\x00" + H2_CONTROL_FRAMES,
        b"\x00" + H2_PUT,
        b"\x00" + H2_GET_CGI,
        b"\x00" + H2_GET_PROXY,
        b"\x00" + H2_GET_NORMALIZED,
        b"\x00" + H2_CONTINUATION,
        b"\x00" + H2_LIFECYCLE_FRAMES,
        b"\x00" + H2_MULTI_STREAM,
        b"\x00" + H2_EXPECT_CONTINUE,
        b"\x00" + H2_REQUEST_TRAILERS,
        b"\x00" + H2_PADDED_DATA,
        b"\x00" + H2_WSTUNNEL_REQUEST,
        b"\x00" + H2_AUTH_WEBDAV_PUT,
        b"\x00" + CHUNKED_EXTENSION_REQUEST,
        b"\x00" + FORWARDED_IPV6_REQUEST,
        b"\x00" + CGI_DENSE_HEADERS,
        b"\x00" + ACCESSLOG_FIELDS_REQUEST,
        b"\x00" + SSI_EXEC_REQUEST,
    ]
    seeds.extend(b"\x00" + request for request in CONDITION_ROUTING_REQUESTS)
    seeds.extend(b"\x00" + request for request in URL_NORMALIZATION_REQUESTS)
    seeds.extend(b"\x00" + request for request in STATIC_PROFILE_REQUESTS)
    seeds.extend(b"\x00" + request for request in USERDIR_EDGE_REQUESTS)
    seeds.extend(b"\x00" + request for request in DEFLATE_REQUESTS)
    seeds.extend(b"\x00" + request for request in PROXY_REQUESTS)
    seeds.extend(b"\x00" + request for request in BACKEND_PROXY_REQUESTS)
    seeds.extend(b"\x00" + request for request in BACKEND_GATEWAY_REQUESTS)
    seeds.extend(b"\x00" + request for request in LEGACY_PROXY_REQUESTS)
    seeds.extend(b"\x00" + request for request in BACKEND_FASTCGI_REQUESTS)
    seeds.extend(b"\x00" + request for request in BACKEND_SCGI_REQUESTS)
    seeds.extend(b"\x00" + request for request in H2_BACKEND_PROXY_REQUESTS)
    seeds.extend(b"\x00" + request for request in H2_BACKEND_FASTCGI_REQUESTS)
    seeds.extend(b"\x00" + request for request in H2_BACKEND_SCGI_REQUESTS)
    seeds.extend(b"\x00" + request for request in FORWARDED_CHAIN_REQUESTS)
    seeds.extend(b"\x00" + request for request in ADMIN_REQUESTS)
    seeds.extend(b"\x00" + request for request in STATUS_VARIANT_REQUESTS)
    seeds.extend(b"\x00" + request for request in STACK_REQUESTS)
    seeds.extend(b"\x00" + request for request in SSI_EDGE_REQUESTS)
    seeds.extend(b"\x00" + request for request in ROUTING_INTERACTION_REQUESTS)
    seeds.extend(b"\x00" + request for request in H2_STATIC_CACHE_REQUESTS)
    seeds.extend(
        multipacket(flags, (GET_KEEPALIVE, GET_FILE))
        for flags in (0x02, 0x03, 0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, (CGI_EXPECT_HEADERS, b"seed"))
        for flags in (0x02, 0x03, 0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, (H2_PREFACE, h2_request_headers(b"GET", b"/")))
        for flags in (0x02, 0x03, 0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, WEBDAV_LIFECYCLE_REQUESTS)
        for flags in (0x02, 0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, WEBDAV_TREE_REQUESTS)
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, WEBDAV_PARTIAL_PUT_REQUESTS)
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, CHUNKED_FRAGMENT_PACKETS)
        for flags in (0x02, 0x03)
    )
    seeds.extend(
        multipacket(flags, CONNECT_TUNNEL_REQUESTS)
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, BACKEND_CONNECT_TUNNEL_REQUESTS)
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, (BACKEND_UPGRADE_REQUEST, b"proxy-upgrade-echo"))
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(
            flags,
            (BACKEND_GATEWAY_UPGRADE_REQUEST, b"gateway-upgrade-echo"),
        )
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, (WSTUNNEL_UPGRADE, WSTUNNEL_BACKEND_FRAME))
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, (H2_WSTUNNEL_HEADERS, H2_WSTUNNEL_DATA))
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, (headers, b"seed"))
        for headers in (BACKEND_FASTCGI_POST_HEADERS, BACKEND_SCGI_POST_HEADERS)
        for flags in (0x02, 0x03)
    )
    seeds.extend(
        multipacket(flags, (b"PROXY TCP6 2001:db8::10 2001:db8::20 12345 80\r\n", FORWARDED_IPV6_REQUEST))
        for flags in (0x02, 0x03)
    )
    seeds.append(multipacket(0x06, LISTING_CACHE_REQUESTS))
    seeds.append(multipacket(0x06, DEFLATE_CACHE_REQUESTS))
    seeds.extend(
        multipacket(
            flags,
            (
                H2C_UPGRADE,
                H2_CONNECTION_PREFACE + H2_SETTINGS,
                h2_request_headers(b"GET", b"/files/index.txt", stream_id=3),
            ),
        )
        for flags in (0x06, 0x07)
    )
    seeds.extend(
        multipacket(flags, (H2_EXPECT_HEADERS, H2_EXPECT_DATA))
        for flags in (0x06, 0x07)
    )
    return seeds


def normalize(data):
    if not data:
        return data
    if data[0] <= 0x07:
        if data[0] & 0x02 and not valid_multipacket(data[1:]):
            return b"\x00" + data
        return bytes([data[0] & 0x07]) + data[1:]
    return b"\x00" + data


def atomic_write(path, data):
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    try:
        temporary.write_bytes(data)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main(argv=None):
    argv = sys.argv if argv is None else argv
    seeds_only = len(argv) == 3 and argv[1] == "--seeds-only"
    if len(argv) != 2 and not seeds_only:
        raise SystemExit(f"usage: {argv[0]} [--seeds-only] CORPUS_DIRECTORY")

    corpus = Path(argv[2] if seeds_only else argv[1])
    corpus.mkdir(parents=True, exist_ok=True)
    changed = 0
    empty = 0
    if not seeds_only:
        for path in corpus.rglob("*"):
            if not path.is_file():
                continue
            data = path.read_bytes()
            if not data:
                empty += 1
                continue
            normalized = normalize(data)
            if normalized != data:
                atomic_write(path, normalized)
                changed += 1

    added = 0
    for seed in seed_inputs():
        path = corpus / hashlib.sha1(seed).hexdigest()
        if not path.exists() or path.read_bytes() != seed:
            atomic_write(path, seed)
            added += 1

    print(
        f"normalized {changed} files; added {added} seed inputs; "
        f"skipped {empty} empty files"
    )


if __name__ == "__main__":
    main()
