#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

cp "$directory/asanProcess.sh" "$test_dir/"
mkdir -p "$test_dir/logs"
cat >"$test_dir/logs/asan1.log.1234" <<'EOF'
==1234==ERROR: AddressSanitizer: heap-use-after-free on address 0x12345678
    #0 0x12345678 in example /tmp/build/src_12345/example.c:12:3
SUMMARY: AddressSanitizer: heap-use-after-free /tmp/build/src_12345/example.c:12:3
AddressSanitizer: CHECK failed: example.cpp:12 "false"
AddressSanitizer:DEADLYSIGNAL
/tmp/build/src_12345/run_987654/example.c:20:4: runtime error: index 9 out of bounds
EOF
cat >"$test_dir/logs/error1" <<'EOF'
ERROR: libFuzzer: timeout after 10 seconds
EOF
cat >"$test_dir/logs/asan2.log.20260921T120000Z-111-1.5678" <<'EOF'
src_2/example.c:30:5: runtime error: harmless test diagnostic
=================================================================
AddressSanitizer: CHECK failed: asan_report.cpp:227 "shutdown" (0x1, 0x0) (tid=5678)
    #0 fuzzer::Fuzzer::ExitCallback()
EOF
printf 'status=72\n' \
    >"$test_dir/logs/asan2.log.20260921T120000Z-111-1.5678.supervisor-stop"
cat >"$test_dir/logs/error2" <<'EOF'
--- supervisor launch 20260921T115900Z-111-1 ---
==5678== ERROR: libFuzzer: fuzz target exited
--- supervisor launch 20260921T120000Z-111-1 ---
==5678== ERROR: libFuzzer: fuzz target exited
AddressSanitizer:DEADLYSIGNAL
AddressSanitizer:DEADLYSIGNAL
SUMMARY: libFuzzer: fuzz target exited
EOF
cat >"$test_dir/logs/asan3.log.9012" <<'EOF'
AddressSanitizer: CHECK failed: asan_report.cpp:227 "test" (0x1, 0x0) (tid=9012)
    #0 fuzzer::Fuzzer::ReportDeadlySignal()
    #1 fuzzer::Fuzzer::RunOne()
EOF
cat >"$test_dir/logs/error3" <<'EOF'
==9012== ERROR: libFuzzer: fuzz target exited
EOF
cat >"$test_dir/logs/asan4.log.20260921T120000Z-111-1.3456" <<'EOF'
AddressSanitizer: CHECK failed: asan_report.cpp:227 "rotated exit" (0x1, 0x0) (tid=3456)
    #0 fuzzer::Fuzzer::ExitCallback()
EOF
printf 'status=72\n' \
    >"$test_dir/logs/asan4.log.20260921T120000Z-111-1.3456.supervisor-stop"
cat >"$test_dir/logs/error4" <<'EOF'
==3456== ERROR: libFuzzer: fuzz target exited
EOF

output="$($test_dir/asanProcess.sh)"
grep -q 'AddressSanitizer: 5' <<<"$output"
grep -q 'UBSan: 2' <<<"$output"
grep -q 'libFuzzer: 4' <<<"$output"
grep -q 'Harness shutdown: 1' <<<"$output"
grep -q '==????==ERROR: AddressSanitizer' "$test_dir/asanfiltered.log"
grep -q 'src_?/run_?/example.c:20:4: runtime error' "$test_dir/asanfiltered.log"
grep -q 'src_?/example.c:30:5: runtime error: harmless test diagnostic' "$test_dir/asanfiltered.log"
! grep -q 'CHECK failed: asan_report.cpp:227 "shutdown"' "$test_dir/asanfiltered.log"
test "$(grep -c 'ERROR: AddressSanitizer' "$test_dir/asanfiltered.log")" -eq 1
grep -q 'fuzzer::Fuzzer::ReportDeadlySignal' "$test_dir/asanfiltered.log"
grep -q 'CHECK failed: asan_report.cpp:227 "rotated exit"' "$test_dir/asanfiltered.log"

echo "ASan report processing test passed."
