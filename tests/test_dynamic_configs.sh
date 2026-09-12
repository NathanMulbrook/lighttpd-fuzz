#!/usr/bin/env bash
set -euo pipefail

project_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
test_dir="$(mktemp -d)"
live_pid=""
cleanup() {
    if [ -n "$live_pid" ]; then
        kill -KILL "$live_pid" 2>/dev/null || true
        wait "$live_pid" 2>/dev/null || true
    fi
    rm -rf "$test_dir"
}
trap cleanup EXIT

cp "$project_dir/build.sh" "$project_dir/run.sh" "$test_dir/"
mkdir -p "$test_dir/configs" "$test_dir/toolchain" "$test_dir/bin"
cat >"$test_dir/toolchain/use-llvm.sh" <<'EOF'
export LLVM_ROOT=/tmp/mock-llvm
export CC=cc
export CXX=c++
EOF
chmod +x "$test_dir/build.sh" "$test_dir/run.sh"

# Lexical ordering would place 10 before 2. Discovery must sort numerically and
# report the first actual gap in a configuration set.
touch "$test_dir/configs/config-1.conf.in"
touch "$test_dir/configs/config-2.conf.in"
touch "$test_dir/configs/config-10.conf.in"
if "$test_dir/build.sh" --config=1 >"$test_dir/gap.out" 2>&1; then
    echo "A gapped configuration set was accepted." >&2
    exit 1
fi
grep -q 'expected 3, found 10' "$test_dir/gap.out"

rm "$test_dir/configs/config-10.conf.in"
for config_id in $(seq 3 12); do
    touch "$test_dir/configs/config-$config_id.conf.in"
done
if "$test_dir/run.sh" --config=13 >"$test_dir/missing.out" 2>&1; then
    echo "A missing configuration ID was accepted." >&2
    exit 1
fi
grep -q "Run configuration '13' is not available" "$test_dir/missing.out"
grep -q 'Available configurations: 1 2 3 4 5 6 7 8 9 10 11 12' "$test_dir/missing.out"

touch "$test_dir/configs/config-01.conf.in"
if "$test_dir/build.sh" --config=1 >"$test_dir/noncanonical.out" 2>&1; then
    echo "A noncanonical numeric configuration filename was accepted." >&2
    exit 1
fi
grep -q 'Invalid configuration template name: config-01.conf.in' "$test_dir/noncanonical.out"
rm "$test_dir/configs/config-01.conf.in"

# A 78-core host with bare -j (10 make jobs per build) must cap the outer
# scheduler at seven concurrent configurations.
mkdir -p "$test_dir/lighttpd/.git"
cat >"$test_dir/bin/nproc" <<'EOF'
#!/usr/bin/env bash
echo 78
EOF
cat >"$test_dir/bin/git" <<'EOF'
#!/usr/bin/env bash
case " $* " in
*' cat-file '*) exit 0 ;;
*' archive '*) exit 1 ;;
*) exit 1 ;;
esac
EOF
chmod +x "$test_dir/bin/nproc" "$test_dir/bin/git"

# A build must fail without signalling a selected profile that is already
# running.  Staging files below a live executable would otherwise split the
# process from the runtime tree it is using.
mkdir -p "$test_dir/run/run_1/sbin" "$test_dir/run/run_1/config" "$test_dir/run/run_1/lib"
cat >"$test_dir/live-lighttpd.c" <<'EOF'
#include <signal.h>
#include <unistd.h>
static void stop(int sig) { (void)sig; _exit(99); }
int main(void) {
    signal(SIGUSR2, stop);
    signal(SIGTERM, stop);
    for (;;) pause();
}
EOF
cc "$test_dir/live-lighttpd.c" -o "$test_dir/run/run_1/sbin/lighttpd"
touch "$test_dir/run/run_1/config/lighttpd.conf"
touch "$test_dir/run/run_1/config/alternate.conf"
"$test_dir/run/run_1/sbin/lighttpd" -D -f "$test_dir/run/run_1/config/alternate.conf" \
    -m "$test_dir/run/run_1/lib" -F &
live_pid="$!"
printf '%s\n' "$live_pid" >"$test_dir/run/run_1/lighttpd.pid"
if PATH="$test_dir/bin:$PATH" "$test_dir/build.sh" --config=1 --no-patch \
    >"$test_dir/active-build.out" 2>&1; then
    echo "A build proceeded while its selected profile was running." >&2
    exit 1
fi
grep -Fq "Refusing to build or stage active lighttpd profiles: 1:$live_pid" \
    "$test_dir/active-build.out"
kill -0 "$live_pid"
kill -KILL "$live_pid"
wait "$live_pid" 2>/dev/null || true
live_pid=""
rm -rf "$test_dir/run"

# The lock closes the PID-file startup race between run.sh and destructive
# build staging.
mkdir -p "$test_dir/run/.locks"
exec {profile_lock_fd}>"$test_dir/run/.locks/config-1.lock"
flock -n "$profile_lock_fd"
if PATH="$test_dir/bin:$PATH" "$test_dir/build.sh" --config=1 --no-patch \
    >"$test_dir/locked-build.out" 2>&1; then
    echo "A build proceeded while the profile lock was held." >&2
    exit 1
fi
grep -Fq 'Configuration 1 is owned by another build or run.sh supervisor' \
    "$test_dir/locked-build.out"
exec {profile_lock_fd}>&-
rm -rf "$test_dir/run"

if PATH="$test_dir/bin:$PATH" "$test_dir/build.sh" --no-patch -j >"$test_dir/scheduler.out" 2>&1; then
    echo "The deliberately failed mock build unexpectedly succeeded." >&2
    exit 1
fi
grep -q 'Building up to 7 configurations concurrently (10 make jobs each; 78 cores detected).' "$test_dir/scheduler.out"

# Leading-zero job counts are decimal inputs rather than invalid octal syntax.
if PATH="$test_dir/bin:$PATH" "$test_dir/build.sh" --no-patch -j08 >"$test_dir/decimal-jobs.out" 2>&1; then
    echo "The deliberately failed mock build unexpectedly succeeded." >&2
    exit 1
fi
grep -q 'Building up to 9 configurations concurrently (8 make jobs each; 78 cores detected).' "$test_dir/decimal-jobs.out"

cat >"$test_dir/bin/tcpdump" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "${!#}" >"$MOCK_FILTER_FILE"
trap 'exit 0' TERM
while sleep 1; do :; done
EOF
cat >"$test_dir/mock-lighttpd" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >>"$MOCK_SERVERS_FILE"
if [[ "$*" == *'/run_1/config/lighttpd.conf'* ]]; then
    starts="$(grep -Fc '/run_1/config/lighttpd.conf' "$MOCK_SERVERS_FILE")"
    [ "$starts" -eq 1 ] && exit 42
fi
trap 'exit 0' TERM
while sleep 1; do :; done
EOF
chmod +x "$test_dir/bin/tcpdump" "$test_dir/mock-lighttpd"
for config_id in $(seq 1 12); do
    run_dir="$test_dir/run/run_$config_id"
    mkdir -p "$run_dir/sbin" "$run_dir/config" "$run_dir/lib"
    cp "$test_dir/mock-lighttpd" "$run_dir/sbin/lighttpd"
    touch "$run_dir/config/lighttpd.conf"
    touch "$run_dir/config/variant.conf"
done

set +e
PATH="$test_dir/bin:$PATH" \
    MOCK_FILTER_FILE="$test_dir/filter.out" \
    MOCK_SERVERS_FILE="$test_dir/servers.out" \
    timeout 7 "$test_dir/run.sh" --fuzz --packet >"$test_dir/run.out" 2>&1
run_status="$?"
set -e
[ "$run_status" -eq 124 ]
expected_filter='tcp and (port 5601 or port 5602 or port 5603 or port 5604 or port 5605 or port 5606 or port 5607 or port 5608 or port 5609 or port 5610 or port 5611 or port 5612)'
grep -Fqx "$expected_filter" "$test_dir/filter.out"
[ "$(wc -l <"$test_dir/servers.out")" -eq 13 ]
grep -Eq 'Config 1 child [0-9]+ exited with status 42 after [0-9]+s; restarting \(rapid attempt 1/5\)\.' "$test_dir/run.out"
grep -Eq 'Config 1 restarted as child [0-9]+\.' "$test_dir/run.out"
grep -Fq -- '--- supervisor restarting config 1 at ' "$test_dir/logs/error1"
for config_id in $(seq 1 12); do
    grep -Fq "run_$config_id/config/lighttpd.conf" "$test_dir/servers.out"
    [ "$(find "$test_dir/logs/profiles" -mindepth 2 -maxdepth 2 -type d -name "run_$config_id" | wc -l)" -eq 1 ]
done

# Backend profiles start one supervised fixture process, wait for its ready
# file, and stop it with the campaign.
cat >"$test_dir/backend-responder.py" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >"$MOCK_BACKEND_ARGS_FILE"
printf '%s\n' "$$" >"$MOCK_BACKEND_PID_FILE"
ready_file=""
while [ "$#" -gt 0 ]; do
    if [ "$1" = "--ready-file" ]; then
        ready_file="$2"
        shift 2
    else
        shift
    fi
done
printf 'http=6501\nfastcgi=6502\nscgi=6503\n' >"$ready_file"
trap 'rm -f "$ready_file"; exit 0' TERM
while sleep 1; do :; done
EOF
chmod +x "$test_dir/backend-responder.py"
printf '%s\n' '"port" => 6501' >"$test_dir/run/run_2/config/variant.conf"

set +e
PATH="$test_dir/bin:$PATH" \
    MOCK_BACKEND_ARGS_FILE="$test_dir/backend-args.out" \
    MOCK_BACKEND_PID_FILE="$test_dir/backend-pid.out" \
    MOCK_SERVERS_FILE="$test_dir/servers.out" \
    timeout 7 "$test_dir/run.sh" --fuzz --config=2 --LOG_OUTPUT \
    >"$test_dir/backend-run.out" 2>&1
backend_run_status="$?"
set -e
[ "$backend_run_status" -eq 124 ]
grep -Fq -- '--http-port 6501 --fastcgi-port 6502 --scgi-port 6503 --ready-file' \
    "$test_dir/backend-args.out"
grep -Eq 'Backend responder [0-9]+ is ready on 127\.0\.0\.1 ports 6501-6503\.' \
    "$test_dir/backend-run.out"
[ ! -e "$test_dir/logs/backend" ]
[ "$(find "$test_dir/logs/profiles" -mindepth 2 -maxdepth 2 -type f -name backend.log | wc -l)" -eq 1 ]
backend_pid="$(cat "$test_dir/backend-pid.out")"
if kill -0 "$backend_pid" 2>/dev/null; then
    echo "Backend responder $backend_pid survived campaign cleanup." >&2
    exit 1
fi

echo "Dynamic configuration discovery and scheduling tests passed."
