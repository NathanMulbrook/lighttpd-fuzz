#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
source "$project_dir/toolchain/use-llvm.sh"
test_dir="$(mktemp -d)"
child_pid=""

if grep -Eq '^[[:space:]]*server\.(errorlog|breakagelog)[[:space:]]*=' \
    "$project_dir/configs/common.conf.in"; then
    echo "The common configuration redirects output away from logs/errorN." >&2
    exit 1
fi

cleanup() {
    if [ -n "$child_pid" ]; then
        kill "$child_pid" 2>/dev/null || true
        wait "$child_pid" 2>/dev/null || true
    fi
    rm -rf "$test_dir"
}
trap cleanup EXIT

cp "$project_dir/status.sh" "$test_dir/"
mkdir -p "$test_dir/configs" "$test_dir/corpus" \
    "$test_dir/logs" "$test_dir/run/run_1/sbin" "$test_dir/run/run_1/config" \
    "$test_dir/run/run_2/sbin"
touch "$test_dir/configs/config-1.conf.in" "$test_dir/configs/config-2.conf.in"
touch "$test_dir/run/run_1/config/lighttpd.conf"
printf 'seed\n' > "$test_dir/corpus/seed"

cat > "$test_dir/mock-lighttpd.c" <<'EOF'
#include <unistd.h>
int main(void) {
    sleep(30);
    return 0;
}
EOF
"$CC" "$test_dir/mock-lighttpd.c" -o "$test_dir/run/run_1/sbin/lighttpd"
"$test_dir/run/run_1/sbin/lighttpd" -D -f \
    "$test_dir/run/run_1/config/lighttpd.conf" -F &
child_pid="$!"
printf '%s\n' "$child_pid" > "$test_dir/run/run_1/lighttpd.pid"
cat > "$test_dir/logs/error1" <<'EOF'
#128 pulse  cov: 100 ft: 120 corp: 12/1Kb exec/s: 50 rss: 25Mb
EOF

output="$($test_dir/status.sh)"
grep -Fq 'Profiles: 1 fuzzing, 0 server-only, 1 stopped' <<< "$output"
grep -Eq 'config +1 +fuzzing +pid=[0-9]+ cpu=.*#128 pulse' <<< "$output"
grep -Eq 'config +2 +stopped' <<< "$output"

single="$($test_dir/status.sh --config=1)"
grep -Fq 'Profiles: 1 fuzzing, 0 server-only, 0 stopped' <<< "$single"

rm "$test_dir/run/run_1/lighttpd.pid"
without_pid="$($test_dir/status.sh --config=1)"
grep -Fq 'Profiles: 1 fuzzing, 0 server-only, 0 stopped' <<< "$without_pid"
grep -Eq 'config +1 +fuzzing +pid=[0-9]+' <<< "$without_pid"

echo "Campaign status test passed."
