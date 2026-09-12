#!/bin/bash
set -euo pipefail

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 PID [output_dir]"
    exit 1
fi

pid="$1"
output_dir="${2:-.}"
if ! ps -p "$pid" >/dev/null; then
    echo "Process $pid not found"
    exit 1
fi

binary="$(readlink "/proc/$pid/exe")"
name="$(basename "$binary").$pid.sancov"
mkdir -p "$output_dir"
gdb -n -p "$pid" -batch 2>/dev/null -ex "print (void)__sanitizer_cov_set_filename(\"$output_dir/$name\")" -ex "print (void)__sanitizer_cov_dump()" -ex "detach" -ex "quit"

if [ ! -f "$output_dir/$name" ]; then
    echo "Coverage dump failed"
    exit 1
fi
echo "Coverage data: $output_dir/$name"
