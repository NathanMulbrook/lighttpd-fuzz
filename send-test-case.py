#!/usr/bin/env python3

"""Send a raw HTTP request, optionally extracted from a fuzzer input."""

import argparse
import socket
import sys
import time
from pathlib import Path


def fuzzer_packets(data):
    if not data:
        raise ValueError("empty fuzzer input")
    if not data[0] & 0x02:
        return [data[1:]]

    packets = []
    offset = 1
    while offset < len(data):
        if len(data) - offset < 2:
            raise ValueError("truncated packet length")
        length = int.from_bytes(data[offset : offset + 2], "big")
        offset += 2
        end = offset + length
        if length == 0 or end > len(data):
            raise ValueError("invalid packet length")
        packets.append(data[offset:end])
        if len(packets) > 64:
            raise ValueError("too many packets")
        offset = end
    if not packets:
        raise ValueError("fuzzer input has no packets")
    return packets


def receive(sock, timeout):
    response = bytearray()
    sock.settimeout(timeout)
    while len(response) < 1024 * 1024:
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            break
        response.extend(chunk)
    return bytes(response)


def receive_some(sock, timeout):
    sock.settimeout(timeout)
    try:
        return sock.recv(8192)
    except socket.timeout:
        return b""


def connect(host, port, timeout):
    return socket.create_connection((host, port), timeout=timeout)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="raw request or fuzzer input")
    parser.add_argument(
        "--packet", type=int, metavar="N", help="extract packet N from fuzzer input"
    )
    parser.add_argument(
        "--fuzzer-input",
        action="store_true",
        help="send all packets using the input's framing and wait flag",
    )
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=7601)
    parser.add_argument("--timeout", type=float, default=1.0)
    args = parser.parse_args(argv)

    data = args.input.read_bytes()
    flags = data[0] if data and (args.packet is not None or args.fuzzer_input) else 0
    if args.packet is not None:
        if args.packet < 1:
            parser.error("--packet must be at least 1")
        packets = fuzzer_packets(data)
        if args.packet > len(packets):
            raise ValueError(f"fuzzer input contains only {len(packets)} packets")
        packets = [packets[args.packet - 1]]
    elif args.fuzzer_input:
        packets = fuzzer_packets(data)
    else:
        packets = [data]

    with connect(args.host, args.port, args.timeout) as sock:
        for number, packet in enumerate(packets, 1):
            print(f"Sending packet {number}: {len(packet)} bytes")
            if flags & 0x01 and len(packet) > 1:
                split = len(packet) // 2
                sock.sendall(packet[:split])
                time.sleep(0.0001)
                sock.sendall(packet[split:])
            else:
                sock.sendall(packet)
            if number < len(packets) and flags & 0x04:
                response = receive_some(sock, args.timeout)
                print(response.decode("latin-1", errors="replace"))
            elif number < len(packets):
                time.sleep(0.001)
        response = receive(sock, args.timeout)
        if response:
            print(response.decode("latin-1", errors="replace"))
        else:
            print("No response before timeout")

    try:
        with connect(args.host, args.port, args.timeout):
            print("Server status: reachable")
    except OSError:
        print("Server status: unreachable")
        return 1
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (OSError, ValueError) as error:
        print(f"Error: {error}", file=sys.stderr)
        sys.exit(1)
