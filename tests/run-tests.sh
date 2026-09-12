#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$directory/toolchain/use-llvm.sh"

mkdir -p "$directory/testTools"
"$CC" -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Werror "$directory/fuzzer.c" "$directory/tests/test_fuzzer.c" -pthread -o "$directory/testTools/test_fuzzer"
"$directory/testTools/test_fuzzer"
python3 -m unittest -v "$directory/tests/test_tools.py"
python3 -m unittest -v "$directory/tests/test_backend_responder.py"
"$directory/tests/test_asan_process.sh"
"$directory/tests/test_sanitizer_policy.sh"
"$directory/tests/test_status.sh"
bash "$directory/tests/test_dynamic_configs.sh"
(
    cd "$directory/build-check"
    python3 -m unittest -v test_check_build.py
)
for patch_dir in \
    "$directory/lighttpd-patches/patches" \
    "$directory/lighttpd-patches-private/findings"; do
    [ -d "$patch_dir" ] || continue
    while IFS= read -r -d '' patch_file; do
        git -C "$directory/lighttpd" apply --check "$patch_file"
    done < <(find "$patch_dir" -mindepth 1 -maxdepth 2 -type f -name '*.patch' -print0 | sort -z)
done

echo "All harness tests passed."
