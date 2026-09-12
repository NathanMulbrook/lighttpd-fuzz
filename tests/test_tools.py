import importlib.util
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


normalizer = load("normalizer", "normalize-corpus-flags.py")
sender = load("sender", "send-test-case.py")
backend = load("backend_responder", "backend-responder.py")


class MultipacketTests(unittest.TestCase):
    def test_seed_frames_round_trip(self):
        for flags in (0x02, 0x03, 0x06, 0x07):
            framed = normalizer.multipacket(
                flags, (normalizer.GET_KEEPALIVE, normalizer.GET_FILE)
            )
            self.assertTrue(normalizer.valid_multipacket(framed[1:]))
            self.assertEqual(
                sender.fuzzer_packets(framed),
                [normalizer.GET_KEEPALIVE, normalizer.GET_FILE],
            )

    def test_invalid_frames_are_rejected(self):
        for data in (b"", b"\0", b"\0\0", b"\0\2x"):
            self.assertFalse(normalizer.valid_multipacket(data))
        with self.assertRaises(ValueError):
            sender.fuzzer_packets(b"\x02\x00\x02x")

    def test_raw_request_gets_control_byte(self):
        self.assertEqual(
            normalizer.normalize(normalizer.GET_ROOT), b"\0" + normalizer.GET_ROOT
        )

    def test_normalizer_is_idempotent_and_adds_seeds(self):
        with tempfile.TemporaryDirectory() as temp:
            corpus = Path(temp)
            raw = corpus / "raw"
            raw.write_bytes(normalizer.GET_ROOT)
            normalizer.main(["normalize", str(corpus)])
            first = {path.name: path.read_bytes() for path in corpus.iterdir()}
            normalizer.main(["normalize", str(corpus)])
            second = {path.name: path.read_bytes() for path in corpus.iterdir()}
            self.assertEqual(first, second)
            self.assertEqual(raw.read_bytes(), b"\0" + normalizer.GET_ROOT)
            self.assertGreaterEqual(len(first), len(normalizer.seed_inputs()))

    def test_seeds_only_preserves_campaign_inputs(self):
        with tempfile.TemporaryDirectory() as temp:
            corpus = Path(temp)
            framed = bytes([0x82]) + normalizer.multipacket(
                0x02, (normalizer.GET_KEEPALIVE, normalizer.GET_FILE)
            )[1:]
            campaign_input = corpus / "campaign-input"
            campaign_input.write_bytes(framed)
            normalizer.main(["normalize", "--seeds-only", str(corpus)])
            self.assertEqual(campaign_input.read_bytes(), framed)

    def test_seed_corpus_is_unique_and_well_framed(self):
        seeds = normalizer.seed_inputs()
        self.assertEqual(len(seeds), len(set(seeds)))
        self.assertGreaterEqual(len(seeds), 120)
        for seed in seeds:
            self.assertTrue(seed)
            self.assertLessEqual(seed[0], 0x07)
            if seed[0] & 0x02:
                self.assertTrue(normalizer.valid_multipacket(seed[1:]))

    def test_stateful_seed_sequences_round_trip(self):
        for packets in (
            normalizer.WEBDAV_LIFECYCLE_REQUESTS,
            normalizer.WEBDAV_TREE_REQUESTS,
            normalizer.WEBDAV_PARTIAL_PUT_REQUESTS,
            normalizer.CHUNKED_FRAGMENT_PACKETS,
            normalizer.CONNECT_TUNNEL_REQUESTS,
            normalizer.LISTING_CACHE_REQUESTS,
            normalizer.DEFLATE_CACHE_REQUESTS,
        ):
            framed = normalizer.multipacket(0x06, packets)
            self.assertEqual(sender.fuzzer_packets(framed), list(packets))

        for requests in (
            normalizer.WEBDAV_LIFECYCLE_REQUESTS,
            normalizer.WEBDAV_TREE_REQUESTS,
            normalizer.WEBDAV_PARTIAL_PUT_REQUESTS,
            normalizer.CONNECT_TUNNEL_REQUESTS,
            normalizer.LISTING_CACHE_REQUESTS,
            normalizer.DEFLATE_CACHE_REQUESTS,
        ):
            for request in requests[:-1]:
                self.assertIn(b"Connection: keep-alive\r\n", request)
            self.assertIn(b"Connection: close\r\n", requests[-1])

    def test_fragmented_chunk_seed_never_waits_for_an_incomplete_request(self):
        seeds = set(normalizer.seed_inputs())
        for flags in (0x02, 0x03):
            self.assertIn(
                normalizer.multipacket(flags, normalizer.CHUNKED_FRAGMENT_PACKETS),
                seeds,
            )

    def test_backend_state_transitions_use_response_wait_packets(self):
        seeds = set(normalizer.seed_inputs())
        sequences = (
            normalizer.BACKEND_CONNECT_TUNNEL_REQUESTS,
            (normalizer.BACKEND_UPGRADE_REQUEST, b"proxy-upgrade-echo"),
            (
                normalizer.BACKEND_GATEWAY_UPGRADE_REQUEST,
                b"gateway-upgrade-echo",
            ),
        )
        for packets in sequences:
            for flags in (0x06, 0x07):
                framed = normalizer.multipacket(flags, packets)
                self.assertIn(framed, seeds)
                self.assertEqual(sender.fuzzer_packets(framed), list(packets))

        for headers in (
            normalizer.BACKEND_FASTCGI_POST_HEADERS,
            normalizer.BACKEND_SCGI_POST_HEADERS,
        ):
            for flags in (0x02, 0x03):
                self.assertIn(
                    normalizer.multipacket(flags, (headers, b"seed")), seeds
                )
        for flags in (0x06, 0x07):
            self.assertNotIn(
                normalizer.multipacket(flags, normalizer.CHUNKED_FRAGMENT_PACKETS),
                seeds,
            )


class ProtocolSeedTests(unittest.TestCase):
    @staticmethod
    def h2_frames(data):
        prefix = normalizer.H2_CONNECTION_PREFACE
        if not data.startswith(prefix):
            raise AssertionError("missing HTTP/2 connection preface")
        frames = []
        offset = len(prefix)
        while offset < len(data):
            if len(data) - offset < 9:
                raise AssertionError("truncated HTTP/2 frame header")
            length = int.from_bytes(data[offset : offset + 3], "big")
            frame_type = data[offset + 3]
            flags = data[offset + 4]
            stream_id = int.from_bytes(data[offset + 5 : offset + 9], "big")
            offset += 9
            end = offset + length
            if end > len(data):
                raise AssertionError("truncated HTTP/2 frame payload")
            frames.append((frame_type, flags, stream_id, data[offset:end]))
            offset = end
        return frames

    def test_richer_http2_seeds_have_valid_frame_boundaries(self):
        for seed in (
            normalizer.H2_PREFACE,
            normalizer.H2_GET_ROOT,
            normalizer.H2_GET_STATUS,
            normalizer.H2_CONTROL_FRAMES,
            normalizer.H2_PUT,
            normalizer.H2_GET_CGI,
            normalizer.H2_GET_PROXY,
            normalizer.H2_GET_NORMALIZED,
            normalizer.H2_CONTINUATION,
            normalizer.H2_LIFECYCLE_FRAMES,
            normalizer.H2_MULTI_STREAM,
            normalizer.H2_EXPECT_CONTINUE,
            normalizer.H2_REQUEST_TRAILERS,
            normalizer.H2_PADDED_DATA,
        ):
            frames = self.h2_frames(seed)
            self.assertTrue(frames)
            self.assertEqual(frames[0][0], 0x04)
            for frame_type, _flags, stream_id, payload in frames:
                if frame_type in (0x04, 0x06):
                    self.assertEqual(stream_id, 0)
                if frame_type == 0x04:
                    self.assertEqual(len(payload) % 6, 0)
                if frame_type == 0x06:
                    self.assertEqual(len(payload), 8)
                if frame_type == 0x08:
                    self.assertEqual(len(payload), 4)
                if frame_type == 0x02:
                    self.assertEqual(len(payload), 5)
                    self.assertNotEqual(stream_id, 0)
                if frame_type in (0x03, 0x07):
                    self.assertEqual(len(payload), 4 if frame_type == 0x03 else 8)

        root_frames = self.h2_frames(normalizer.H2_GET_ROOT)
        self.assertEqual(root_frames[-1][0:3], (0x01, 0x05, 1))
        self.assertIn(b"localhost", root_frames[-1][3])

        put_frames = self.h2_frames(normalizer.H2_PUT)
        self.assertEqual(put_frames[-2][0:3], (0x01, 0x04, 1))
        self.assertEqual(put_frames[-1], (0x00, 0x01, 1, b"seed"))

        continuation_frames = self.h2_frames(normalizer.H2_CONTINUATION)
        self.assertEqual(continuation_frames[-2][0:3], (0x01, 0x01, 1))
        self.assertEqual(continuation_frames[-1][0:3], (0x09, 0x04, 1))

        multi_stream_frames = self.h2_frames(normalizer.H2_MULTI_STREAM)
        self.assertEqual(
            [frame[2] for frame in multi_stream_frames if frame[0] == 0x01],
            [1, 3, 5],
        )

        expect_frames = self.h2_frames(normalizer.H2_EXPECT_CONTINUE)
        self.assertEqual(expect_frames[-1], (0x00, 0x01, 1, b"seed"))
        self.assertEqual(normalizer.H2_EXPECT_CONTINUE,
                         normalizer.H2_EXPECT_HEADERS + normalizer.H2_EXPECT_DATA)

        trailer_frames = self.h2_frames(normalizer.H2_REQUEST_TRAILERS)
        self.assertEqual(trailer_frames[-1][0:3], (0x01, 0x05, 1))
        self.assertIn(b"test-trailer", trailer_frames[-1][3])

        padded_frames = self.h2_frames(normalizer.H2_PADDED_DATA)
        self.assertEqual(padded_frames[-1], (0x00, 0x09, 1, b"\x02seed\x00\x00"))

    def test_seed_content_lengths_match_bodies(self):
        for request in (
            normalizer.CGI_POST,
            normalizer.WEBDAV_PROPFIND,
            normalizer.WEBDAV_LIFECYCLE_REQUESTS[1],
            normalizer.WEBDAV_TREE_REQUESTS[2],
            normalizer.WEBDAV_PARTIAL_PUT_REQUESTS[0],
            normalizer.WEBDAV_PARTIAL_PUT_REQUESTS[1],
        ):
            headers, body = request.split(b"\r\n\r\n", 1)
            content_length = next(
                line for line in headers.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            expected = int(content_length.split(b":", 1)[1])
            self.assertEqual(expected, len(body))

        for headers in (
            normalizer.BACKEND_FASTCGI_POST_HEADERS,
            normalizer.BACKEND_SCGI_POST_HEADERS,
        ):
            content_length = next(
                line for line in headers.split(b"\r\n")
                if line.lower().startswith(b"content-length:")
            )
            self.assertEqual(int(content_length.split(b":", 1)[1]), 4)

    def test_backend_mode_seeds_cover_each_protocol_route(self):
        modes = normalizer.BACKEND_RESPONSE_MODES
        self.assertEqual(len(modes), len(set(modes)))
        self.assertEqual(tuple(mode.decode() for mode in modes), backend.MODE_NAMES)
        route_sets = (
            normalizer.BACKEND_PROXY_REQUESTS,
            normalizer.BACKEND_GATEWAY_REQUESTS,
            normalizer.BACKEND_FASTCGI_REQUESTS,
            normalizer.BACKEND_SCGI_REQUESTS,
        )
        h2_sets = (
            normalizer.H2_BACKEND_PROXY_REQUESTS,
            normalizer.H2_BACKEND_FASTCGI_REQUESTS,
            normalizer.H2_BACKEND_SCGI_REQUESTS,
        )
        for requests in route_sets:
            self.assertEqual(len(requests), len(modes))
            for request, mode in zip(requests, modes):
                self.assertIn(b"/" + mode + b" HTTP/1.1\r\n", request)
        for requests in h2_sets:
            self.assertEqual(len(requests), len(modes))
            for request in requests:
                self.assertTrue(self.h2_frames(request))

    def test_haproxy_v2_tlv_seed_has_exact_declared_length(self):
        data = normalizer.HAPROXY_V2_TLV_GET
        self.assertEqual(data[:12], bytes.fromhex("0d0a0d0a000d0a515549540a"))
        declared = int.from_bytes(data[14:16], "big")
        self.assertEqual(data[16 + declared : 20 + declared], b"GET ")

    def test_dense_cgi_seed_fits_request_field_limit(self):
        headers, body = normalizer.CGI_DENSE_HEADERS.split(b"\r\n\r\n", 1)
        generated = [line for line in headers.split(b"\r\n") if line.startswith(b"X")]
        self.assertEqual(len(generated), 1050)
        self.assertEqual(len(generated), len(set(generated)))
        self.assertLess(len(headers) + 4, 8192)
        self.assertEqual(body, b"")


class FixtureTests(unittest.TestCase):
    def test_expanded_profile_fixtures_are_present(self):
        docroot = ROOT / "configs" / "docroot"
        required = (
            "errors/404.html",
            "errors/status-404.html",
            "files/large.txt",
            "listing/HEADER.txt",
            "listing/README.txt",
            "listing.css",
            "listing.js",
            "cgi/echo.cgi",
            "ssi/index.shtml",
            "ssi/include.shtml",
            "ssi/raw.ssi",
            "digest/index.txt",
            "basic-user/index.txt",
            "vhosts/default.example/htdocs/index.html",
            "vhosts/one.example/htdocs/index.html",
            "evhosts/www/example.org/htdocs/index.html",
            "users/f/fuzz/public_html/index.html",
            "static/no-etag/large.txt",
            "static/pathinfo/large.txt",
        )
        for relative in required:
            self.assertTrue((docroot / relative).is_file(), relative)

        self.assertGreaterEqual((docroot / "files/large.txt").stat().st_size, 4096)
        for relative in ("static/link.txt", "no-follow/link.txt"):
            link = docroot / relative
            self.assertTrue(link.is_symlink(), relative)
            self.assertTrue(link.resolve().is_file(), relative)
        listing_entries = list((docroot / "listing").iterdir())
        self.assertGreater(len(listing_entries), 32)


if __name__ == "__main__":
    unittest.main()
