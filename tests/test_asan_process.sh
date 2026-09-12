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

output="$($test_dir/asanProcess.sh)"
grep -q 'AddressSanitizer: 3' <<<"$output"
grep -q 'UBSan: 1' <<<"$output"
grep -q 'libFuzzer: 1' <<<"$output"
grep -q '==????==ERROR: AddressSanitizer' "$test_dir/asanfiltered.log"
grep -q 'src_?/run_?/example.c:20:4: runtime error' "$test_dir/asanfiltered.log"
test "$(grep -c 'ERROR: AddressSanitizer' "$test_dir/asanfiltered.log")" -eq 1

echo "ASan report processing test passed."
