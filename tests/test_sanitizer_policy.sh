#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$directory/toolchain/use-llvm.sh"

test_dir="$(mktemp -d)"
trap 'rm -rf "$test_dir"' EXIT

cat >"$test_dir/recover.c" <<'EOF'
#include <limits.h>
#include <stdio.h>

int main(void) {
    volatile int value = INT_MAX;
    volatile int result = value + 1;
    printf("continued after UBSan: %d\n", result);
    return 0;
}
EOF

"$CC" -O1 -g -fsanitize=undefined -fsanitize-recover=all \
    "$test_dir/recover.c" -o "$test_dir/recover"

UBSAN_OPTIONS="print_stacktrace=1:halt_on_error=0:log_path=$test_dir/ubsan" \
    "$test_dir/recover" >"$test_dir/output"

grep -q '^continued after UBSan:' "$test_dir/output"
grep -q 'runtime error: signed integer overflow' "$test_dir"/ubsan.*
grep -Fq 'local ubsan_options="print_stacktrace=1:halt_on_error=0:' "$directory/run.sh"
grep -Fq -- '-fsanitize-recover=all' "$directory/build.sh"

echo "Recoverable UBSan policy test passed."
