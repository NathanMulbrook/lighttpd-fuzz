#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$directory/toolchain/use-llvm.sh"

if [ "$#" -ne 2 ]; then
    echo "Usage: ./genreport.sh PROFILE_SESSION BUILD_CONFIG|all"
    echo "Example: ./genreport.sh logs/profiles/20260911T190000Z-1234 1"
    echo "         ./genreport.sh logs/profiles/20260911T190000Z-1234 all"
    exit 1
fi

profile_session="$(realpath "$1")"
build_config="$2"
if [ "$build_config" = "all" ]; then
    profile_dir="$profile_session"
    run_dir="$directory/run/run_1"
    report_name="aggregate"
elif [[ "$build_config" =~ ^[1-9][0-9]*$ ]]; then
    profile_dir="$profile_session/run_$build_config"
    run_dir="$directory/run/run_$build_config"
    report_name="run_$build_config"
else
    echo "BUILD_CONFIG must be a positive integer or 'all'."
    exit 1
fi
binary="$run_dir/sbin/lighttpd"
report_dir="$directory/logs/coverage/$(basename "$profile_session")/$report_name"

if [ ! -x "$binary" ]; then
    echo "Missing fuzzer binary: $binary"
    exit 1
fi

mapfile -t profiles < <(find "$profile_dir" -type f -name '*.profraw' -size +0c | sort)
if [ "${#profiles[@]}" -eq 0 ]; then
    echo "No profiles found in $profile_dir"
    exit 1
fi

mapfile -t objects < <(
    # The target executable and loadable modules form one instrumented process.
    # Do not include sibling programs such as lighttpd-angel; it has its own
    # unrelated main() and therefore produces a misleading profile-hash warning.
    find "$run_dir/lib" -type f | while IFS= read -r file; do
        if readelf -SW "$file" 2>/dev/null | grep -q '__llvm_covmap'; then
            printf '%s\n' "$file"
        fi
    done | sort -u
)

object_args=()
for object in "${objects[@]}"; do
    if [ "$object" != "$binary" ]; then
        object_args+=(-object "$object")
    fi
done

mkdir -p "$report_dir"
llvm-profdata merge -sparse "${profiles[@]}" -o "$report_dir/coverage.profdata"
llvm-cov report "$binary" "${object_args[@]}" -instr-profile="$report_dir/coverage.profdata" >"$report_dir/coverage.txt"
llvm-cov show "$binary" "${object_args[@]}" -format=html -instr-profile="$report_dir/coverage.profdata" >"$report_dir/coverage.html"

echo "Coverage report: $report_dir/coverage.txt"
echo "Coverage HTML: $report_dir/coverage.html"
