# lighttpd-fuzz

This is a small in-process libFuzzer setup for lighttpd, ported from the
neighboring 389 DS fuzzing project. The upstream checkout remains clean:
`build.sh` exports the pinned revision into `build/src_N`, applies the small
integration patch and confirmed fixes from the private findings checkout
there, and installs each instrumented variant under `run/run_N`.

The fuzzer runs in a pthread inside lighttpd and sends data over IPv4 loopback.
This keeps production socket, event-loop, HTTP parsing, plugin, and response
paths in the same process as libFuzzer's coverage counters.

## Toolchain and first build

The scripts use the project-local LLVM 23.1.1 toolchain in `toolchain/`.
This workspace already contains it. To recreate it on another machine, run:

```console
./build.sh --bootstrap-toolchain
```

Build and stage all 47 configurations:

```console
./build.sh --directory --jobs
```

The short form is `./build.sh -d -j`. The usual layout and interface are
preserved:

- `build/build_N`: out-of-tree build
- `build/src_N`: temporary patched source
- `run/run_N`: installed binary, modules, fixture files, and configuration
- HTTP port `5600 + N`
- `logs/buildN.log`, `logs/errorN`, `logs/asanN.log*`, and
  `logs/testCasesN`

`-j` uses ten compile jobs per configuration. Use `-jN` or `-j=N` to select a
different number. The outer scheduler also considers the machine's CPU count.
On this 78-CPU host, bare `-j` builds up to seven configurations at once, for
about 70 compiler jobs rather than starting all 47 builds simultaneously.

To build only one profile:

```console
./build.sh -c=23 -d -j
```

`--rebuild-directory` recreates only the runtime configuration and fixtures
from an existing install. `--no_patch` produces a normal instrumented
lighttpd without the embedded driver or known-finding fixes. `--init` clones
upstream when `lighttpd/` is absent.

An alternate compatible LLVM path can still be selected explicitly:

```console
LLVM_ROOT=/path/to/llvm-23.1.1 ./build.sh --config=1 --directory
```

## Running

After the build finishes, start all 47 fuzzing processes:

```console
./run.sh
```

Check process state, CPU use, corpus activity, and the latest libFuzzer pulse:

```console
./status.sh
./status.sh --config=2
```

Each process has a lighttpd event-loop thread, an embedded libFuzzer execution
thread, and a mostly idle libFuzzer timer thread. The full matrix therefore
has about 141 OS threads, with up to 94 doing request and fuzzing work.
Profiles use ports 5601 through 5647.

`build.sh` only compiles and stages profiles; it never starts a server or
fuzzer. It refuses to build or stage a selected profile while that profile is
running, so a build cannot terminate an active campaign. `run.sh` is the
campaign supervisor. It launches one isolated lighttpd process for each
selected configuration and holds a per-profile lock for the life of that
process. It restarts an isolated exit. After five rapid restart attempts, a
sixth exit is treated as an unrecoverable startup loop; that profile stops
while the other processes keep running.

Profiles 21, 22, 37, 40, 41, 42, and 44 use one supervised loopback backend fixture. `run.sh`
starts it automatically before those profiles and stops it after the lighttpd
processes. The fixture listens on ports 6501 (HTTP), 6502 (FastCGI), and 6503
(SCGI). Its output is kept in `logs/profiles/<campaign>/backend.log`. If it
exits unexpectedly, the supervisor stops that campaign so it does not spend
time measuring backend connection failures.

As in the 389 DS runner, `logs/errorN` contains the combined launcher,
lighttpd, and libFuzzer output for profile N. Request records remain in
`run/run_N/access.log` where that profile enables `mod_accesslog`; these logs
are rotated at 100 MB.
At the next launch, an existing `logs/errorN` is moved to
`logs/old/error/<campaign-id>/errorN`, leaving one fresh root log per selected
configuration.

Set `LIGHTTPD_FUZZ_CORPUS=/path/to/corpus` before `./run.sh` to use a
different shared corpus directory. Run `./normalize-corpus-flags.py /path/to/corpus`
once before its first use; build staging adds seeds only to the default corpus.

Or run one:

```console
./run.sh --config=1
```

Add `--packet` to retain timestamped 12-hour tcpdump segments when the account
has packet-capture permission.

Per-input hex logging is intentionally off in normal campaigns because it is
expensive. Add `--test-case-log` when correlating a recoverable UBSan report
with executed inputs. The builds use `-fsanitize-recover=all`, and `run.sh`
sets `UBSAN_OPTIONS=halt_on_error=0`, so recoverable UBSan diagnostics are
written to `logs/asanN.log.PID` while that profile keeps fuzzing. ASan memory
errors, fatal signals, resource-limit failures, and other conditions from
which the process cannot reliably continue remain terminal; libFuzzer then
preserves the current unit under `logs/artifacts/run_N`. Other profile
processes continue independently.

The harness records an enabled test-case log entry, including the process ID
and sequence number, before sending that input. After transmission it keeps
the libFuzzer callback active for 20 ms, closes the client socket, and waits
another 2 ms for EOF cleanup. This mirrors the 389 DS harness's iteration
fence and prevents normal late event-loop coverage or diagnostics from being
credited to the following input. It is a bounded timing fence; unusually slow
asynchronous work still requires replay of the saved input before a finding is
assigned.

As in the 389 DS scripts, `run.sh --fuzz --config=1` disables the embedded
fuzzer and starts only the instrumented server. This is useful for replay:

```console
./send-test-case.py request.bin --port 5601
./send-test-case.py crash-input --packet 2 --port 5601
./send-test-case.py crash-input --fuzzer-input --port 5601
```

Each `run.sh` session writes raw coverage profiles below
`logs/profiles/<UTC-time>-<pid>/run_N`. After stopping it:

```console
./genreport.sh logs/profiles/SESSION_DIRECTORY 1
./genreport.sh logs/profiles/SESSION_DIRECTORY all
```

The numeric form reports one profile. The `all` form merges every configuration
from that campaign into one aggregate text and HTML report.

The builds use LLVM's relocatable counters and continuous profile mode, so a
libFuzzer-aware shutdown preserves source coverage without running target
`atexit` handlers or manufacturing a shutdown crash artifact.

## Input format

The first byte is a control byte:

- bit 0 (`0x01`): split every request across two writes
- bit 1 (`0x02`): interpret the remaining data as multiple packets
- bit 2 (`0x04`): wait for response bytes between packets

Ordinary input is the control byte followed by raw HTTP bytes. Multipacket
input repeats a two-byte big-endian nonzero length followed by that many raw
bytes. It must contain 1-64 complete packets; malformed framing is rejected
before a connection is opened. All packets in an iteration use one connection,
which covers keep-alive, pipelining, chunked bodies, and protocol transitions.

Prepare a raw HTTP corpus and add the tracked seed set with:

```console
./normalize-corpus-flags.py corpus
```

Build staging uses `--seeds-only`, which adds the standard seeds without
rewriting units already produced by a running campaign.

The seeds include HTTP/1.1 static, range, forwarded, authenticated, status,
alias, redirect, rewrite, chunked WebDAV, h2c-upgrade, and HTTP/2 requests,
plus fragmentation and response-wait multipacket sequences. Backend seeds use
ordinary HTTP paths and headers, so the harness format is unchanged. They cover
normal, partial, interim, chunked/trailer, redirect/cookie, early-close,
malformed, truncated, upgrade/echo, CONNECT, FastCGI, and SCGI interactions.

## Runtime configurations

Every profile has a distinct combination of parser policy, event handler,
network backend, streaming mode, or modules:

| ID | Main coverage |
|---:|---|
| 1 | Common production stack: auth, forwarded headers, status, compression, expiry |
| 2 | Relaxed HTTP parsing, rewrite, redirect, alias on `poll`/`writev` |
| 3 | Writable WebDAV and streamed responses |
| 4 | Strict parsing and cleartext HTTP/2 on `epoll`/`sendfile` |
| 5 | Compatibility URL normalization and decoding |
| 6 | Rejection of ambiguous encodings, controls, dot segments, and invalid UTF-8 |
| 7 | Nested conditions, routing, access checks, and error handlers |
| 8 | Rich HTML/JSON directory listings and listing cache |
| 9 | Brotli, zstd, bzip2, gzip, and deflate with disk cache |
| 10 | Writable WebDAV, partial PUT, and inotify invalidation |
| 11 | Buffered CGI, local redirect, and X-Sendfile |
| 12 | Streaming CGI, upgrades, timeouts, and child cleanup |
| 13 | SSI includes, variables, validators, and recursion |
| 14 | Digest/basic auth and credential cache |
| 15 | Simple virtual-host document-root mapping |
| 16 | Enhanced wildcard virtual-host mapping |
| 17 | User-directory mapping and allow/deny rules |
| 18 | Streamed HTTP/2 with status, compression, and WebDAV |
| 19 | Static metadata, ranges, validators, indexes, pathinfo, and symlink policy |
| 20 | HTTP/1 lifecycle, request limits, trailers, bodies, and pipelining |
| 21 | Controlled HTTP, FastCGI, and SCGI backends plus streamed proxy bodies |
| 22 | Controlled hash-balanced proxy with upgrade and CONNECT tunnel paths |
| 23 | HAProxy protocol v1/v2 plus Forwarded and X-Forwarded parsing |
| 24 | Rich access-log formatting and escaping |
| 25 | Status, configuration, and statistics generators |
| 26 | Strict HTTP/1 with HTTP/2 disabled |
| 27 | Permissive HTTP/1 with GET bodies and HTTP/2 disabled |
| 28 | Sorted uncached directory listings and alternate layout |
| 29 | Streaming CGI requests with buffered dynamic-response compression |
| 30 | CGI local redirects, X-Sendfile, and pathinfo |
| 31 | SSI raw output and shallow recursion on `poll`/`writev` |
| 32 | Basic-auth authorization rules without caching |
| 33 | Read-only WebDAV discovery and rejected mutations |
| 34 | Compatibility WebDAV partial PUT and symlink-aware PROPFIND |
| 35 | HTTP/2 with compatibility URL normalization on `poll`/`writev` |
| 36 | HTTP/2 CGI request streaming and buffered dynamic compression |
| 37 | HTTP/2 frontend to controlled HTTP/1, FastCGI, and SCGI backends |
| 38 | Inotify static cache, directory listings, expiry, and compression cache |
| 39 | Production-style routing, auth, CGI, SSI, expiry, status, and compression stack |
| 40 | RFC 6455 WebSocket handshakes, frame parsing, origin checks, and backend I/O |
| 41 | Transparent socket forwarding and least-connection backend selection |
| 42 | RFC 8441 HTTP/2 extended CONNECT WebSockets and tunneled DATA frames |
| 43 | Authenticated HTTP/2 WebDAV mutations, partial PUT, and inotify updates |
| 44 | HTTP/1.0 backend translation, response remapping, forwarding, and buffering |
| 45 | Virtual-host, userdir, alias, rewrite, redirect, and condition interactions |
| 46 | SSI execution, nested includes, validators, and CGI pathinfo |
| 47 | HTTP/2 static ranges, validators, inotify, listings, expiry, and compression |

## Verification and sanitizer review

Run the harness, corpus, backend-protocol, patch, and artifact-checker tests:

```console
./tests/run-tests.sh
```

After building and staging all profiles, exercise the live CGI, compression,
proxy, HAProxy-protocol, and WebDAV paths:

```console
python3 ./tests/test_runtime_profiles.py
```

After building all variants, verify that objects, modules, and binaries contain
the requested ASan, UBSan, libFuzzer-guidance, stack-protector, and source
coverage evidence:

```console
./checkObjects.sh
```

The report is written to `logs/symbolReport.md`. `asanProcess.sh` normalizes
and deduplicates runtime reports into `asanfiltered.log`, including ASan
internal failures and deadly signals; `run.sh` invokes it once per minute.
The runner checks its children every five seconds. If one profile crashes, it
records the exit and restarts that profile. It appends the new process output
to the same `logs/errorN` file, with a restart marker between processes. A
packet-capture failure is also reported without stopping the fuzzers. The
runner exits when no fuzzing profiles remain.

The integration patch is limited to adding `fuzzer.c` to lighttpd, linking
libFuzzer's no-main runtime, adding `-F`, forcing single-process foreground
operation, and launching the driver immediately before the event loop. Any
upstream drift that breaks the pinned patch is a visible build failure.

Confirmed fixes in `lighttpd-patches-private/patches/*.patch`, when that
checkout is present, are also applied only to exported build copies. This lets
campaigns progress beyond known failures without modifying the upstream
checkout. Existing binaries must be rebuilt before a new fix takes effect.
