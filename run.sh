#!/usr/bin/env bash
set -u

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "$directory/toolchain/use-llvm.sh" || exit
if ! command -v setsid >/dev/null; then
    echo "setsid is required to isolate fuzzing children from terminal signals."
    exit 1
fi

FUZZ="-F"
CONFIG="all"
LOG_OUTPUT=1
PACKET_CAPTURE=0
TEST_CASE_LOG=0
profile_dir="$directory/logs/profiles/$(date -u +%Y%m%dT%H%M%SZ)-$$"
campaign_id="${profile_dir##*/}"
error_archive_dir="$directory/logs/old/error/$campaign_id"
mkdir -p "$profile_dir" "$directory/logs/old/build" "$directory/logs/old/error" "$directory/logs/old/asan" "$directory/logs/old/testCases" "$directory/logs/artifacts"

fuzzer_pids=()
capture_pids=()
backend_pids=()
backend_ready_file=""
declare -A fuzzer_configs=()
declare -A server_pid_files=()
CONFIG_IDS=()
selected_configs=()

discover_configs() {
    local config_path filename config_id config_number expected
    local config_paths=()
    shopt -s nullglob
    config_paths=("$directory"/configs/config-[0-9]*.conf.in)
    shopt -u nullglob

    if [ "${#config_paths[@]}" -eq 0 ]; then
        echo "No numeric configuration templates found in $directory/configs."
        return 1
    fi
    for config_path in "${config_paths[@]}"; do
        filename="${config_path##*/}"
        if [[ ! "$filename" =~ ^config-([1-9][0-9]{0,4})\.conf\.in$ ]]; then
            echo "Invalid configuration template name: $filename"
            echo "Use canonical names such as config-1.conf.in."
            return 1
        fi
        config_id="${BASH_REMATCH[1]}"
        config_number="$((10#$config_id))"
        if [ "$config_number" -gt 59935 ]; then
            echo "Configuration $config_id cannot use a TCP port above 65535."
            return 1
        fi
        CONFIG_IDS+=("$config_number")
    done
    mapfile -t CONFIG_IDS < <(printf '%s\n' "${CONFIG_IDS[@]}" | LC_ALL=C sort -n)

    expected=1
    for config_id in "${CONFIG_IDS[@]}"; do
        if [ "$config_id" -ne "$expected" ]; then
            echo "Configuration IDs must be contiguous from 1; expected $expected, found $config_id."
            return 1
        fi
        expected="$((expected + 1))"
    done
}

valid_config() {
    local requested="$1" config_id
    case "$requested" in
    '' | *[!0-9]*) return 1 ;;
    esac
    for config_id in "${CONFIG_IDS[@]}"; do
        [ "$requested" = "$config_id" ] && return 0
    done
    return 1
}

cleanup() {
    local exit_status="$?"
    trap - EXIT
    trap '' INT TERM

    local pid running
    for pid in "${fuzzer_pids[@]}"; do
        if [ -n "$FUZZ" ]; then
            kill -USR2 "$pid" 2>/dev/null || true
        else
            kill -TERM -- "-$pid" 2>/dev/null || true
        fi
    done
    for pid in "${capture_pids[@]}"; do
        kill -TERM -- "-$pid" 2>/dev/null || true
    done

    local child_pids=("${fuzzer_pids[@]}" "${capture_pids[@]}")
    if [ "${#child_pids[@]}" -gt 0 ]; then
        for _ in {1..100}; do
            running=0
            for pid in "${child_pids[@]}"; do
                kill -0 -- "-$pid" 2>/dev/null && running=1
            done
            [ "$running" -eq 0 ] && break
            sleep 0.1
        done
        for pid in "${child_pids[@]}"; do
            if kill -0 -- "-$pid" 2>/dev/null; then
                echo "Terminating remaining processes in campaign group $pid after 10 seconds." >&2
                kill -TERM -- "-$pid" 2>/dev/null || true
            fi
        done
        for _ in {1..20}; do
            running=0
            for pid in "${child_pids[@]}"; do
                kill -0 -- "-$pid" 2>/dev/null && running=1
            done
            [ "$running" -eq 0 ] && break
            sleep 0.1
        done
        for pid in "${child_pids[@]}"; do
            if kill -0 -- "-$pid" 2>/dev/null; then
                echo "Forcing campaign group $pid to stop." >&2
                kill -KILL -- "-$pid" 2>/dev/null || true
            fi
        done
        for pid in "${child_pids[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    fi
    for pid in "${backend_pids[@]}"; do
        kill -TERM -- "-$pid" 2>/dev/null || true
    done
    if [ "${#backend_pids[@]}" -gt 0 ]; then
        for _ in {1..50}; do
            running=0
            for pid in "${backend_pids[@]}"; do
                kill -0 -- "-$pid" 2>/dev/null && running=1
            done
            [ "$running" -eq 0 ] && break
            sleep 0.1
        done
        for pid in "${backend_pids[@]}"; do
            if kill -0 -- "-$pid" 2>/dev/null; then
                echo "Forcing backend responder group $pid to stop." >&2
                kill -KILL -- "-$pid" 2>/dev/null || true
            fi
            wait "$pid" 2>/dev/null || true
        done
    fi
    [ -n "$backend_ready_file" ] && rm -f "$backend_ready_file"
    for pid in "${!server_pid_files[@]}"; do
        local pid_file="${server_pid_files[$pid]}"
        if [ -f "$pid_file" ] && [ "$(sed -n '1p' "$pid_file")" = "$pid" ]; then
            rm -f "$pid_file"
        fi
    done
    exit "$exit_status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

for arg in "$@"; do
    case "$arg" in
    --fuzz | -f)
        FUZZ=""
        ;;
    --packet | -p)
        PACKET_CAPTURE=1
        ;;
    --test-case-log)
        TEST_CASE_LOG=1
        ;;
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    --LOG_OUTPUT | --LOG_OUPTUT | -s)
        LOG_OUTPUT=0
        ;;
    --help | -h)
        echo "Usage: ./run.sh [--config=N|all] [--fuzz] [--packet] [--test-case-log] [--LOG_OUTPUT]"
        echo "  --fuzz disables the embedded fuzzer and runs only the server."
        echo "  --test-case-log records every executed input (slow and disk intensive)."
        exit
        ;;
    esac
done

discover_configs || exit 1
if [ "$CONFIG" = "a" ] || [ "$CONFIG" = "all" ]; then
    selected_configs=("${CONFIG_IDS[@]}")
elif valid_config "$CONFIG"; then
    selected_configs=("$CONFIG")
else
    echo "Run configuration '$CONFIG' is not available."
    echo "Available configurations: ${CONFIG_IDS[*]}"
    exit 1
fi

if [ -n "$FUZZ" ]; then
    echo "Launching ${#selected_configs[@]} fuzzing profiles (about $((${#selected_configs[@]} * 3)) OS threads)."
else
    echo "Launching ${#selected_configs[@]} server-only profiles."
fi

stop_previous() {
    local pid_file="$1"
    local binary="$2"
    local config="$3"
    [ -f "$pid_file" ] || return 0
    local pid actual_exe expected_exe
    pid="$(sed -n '1p' "$pid_file")"
    case "$pid" in
    '' | *[!0-9]*)
        rm -f "$pid_file"
        return 0
        ;;
    esac
    if ! kill -0 "$pid" 2>/dev/null; then
        rm -f "$pid_file"
        return 0
    fi
    actual_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
    actual_exe="${actual_exe% (deleted)}"
    expected_exe="$(realpath -m "$binary")"
    if [ "$actual_exe" != "$expected_exe" ]; then
        echo "Ignoring stale PID file: $pid_file"
        rm -f "$pid_file"
        return 0
    fi
    if ! tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null | grep -Fqx -- "$config"; then
        echo "Ignoring PID file for a different lighttpd invocation: $pid_file"
        rm -f "$pid_file"
        return 0
    fi

    local signal=TERM
    if tr '\0' '\n' <"/proc/$pid/cmdline" 2>/dev/null | grep -Fqx -- '-F'; then
        signal=USR2
    fi
    kill -"$signal" "$pid" 2>/dev/null || true
    for _ in {1..100}; do
        kill -0 "$pid" 2>/dev/null || return 0
        sleep 0.1
    done
    echo "Previous lighttpd process $pid did not stop."
    return 1
}

archive_previous_error_log() {
    local build_config="$1"
    local error_log="$directory/logs/error$build_config"
    [ -e "$error_log" ] || return 0

    mkdir -p "$error_archive_dir"
    mv "$error_log" "$error_archive_dir/error$build_config"
}

selected_configs_require_backend() {
    local build_config variant_config
    for build_config in "${selected_configs[@]}"; do
        variant_config="$directory/run/run_$build_config/config/variant.conf"
        if [ -f "$variant_config" ] \
            && grep -Eq '"port"[[:space:]]*=>[[:space:]]*650[123]' "$variant_config"; then
            return 0
        fi
    done
    return 1
}

start_backend_responder() {
    local responder="$directory/backend-responder.py"
    local backend_log="$profile_dir/backend.log"
    if [ ! -x "$responder" ]; then
        echo "Missing executable backend responder: $responder"
        return 1
    fi

    mkdir -p "$directory/run"
    backend_ready_file="$directory/run/backend-responder.$$.ready"
    rm -f "$backend_ready_file"
    setsid "$responder" \
        --http-port 6501 \
        --fastcgi-port 6502 \
        --scgi-port 6503 \
        --ready-file "$backend_ready_file" \
        --workers 4 \
        >"$backend_log" 2>&1 &
    local pid="$!"
    backend_pids+=("$pid")

    for _ in {1..100}; do
        if [ -f "$backend_ready_file" ]; then
            if grep -Fqx 'http=6501' "$backend_ready_file" \
                && grep -Fqx 'fastcgi=6502' "$backend_ready_file" \
                && grep -Fqx 'scgi=6503' "$backend_ready_file"; then
                echo "Backend responder $pid is ready on 127.0.0.1 ports 6501-6503."
                return 0
            fi
            echo "Backend responder wrote an invalid ready file; see $backend_log."
            return 1
        fi
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            backend_pids=()
            echo "Backend responder exited before becoming ready; see $backend_log."
            return 1
        fi
        sleep 0.1
    done
    echo "Backend responder did not become ready within 10 seconds; see $backend_log."
    return 1
}

run_fuzzer() {
    local build_config="$1"
    valid_config "$build_config" || {
        echo "Run configuration '$build_config' is not available."
        echo "Available configurations: ${CONFIG_IDS[*]}"
        return 1
    }

    local run_dir="$directory/run/run_$build_config"
    local binary="$run_dir/sbin/lighttpd"
    local config="$run_dir/config/lighttpd.conf"
    local variant_config="$run_dir/config/variant.conf"
    local pid_file="$run_dir/lighttpd.pid"
    local config_number="$((10#$build_config))"
    local port="$((5600 + config_number))"
    local config_profile_dir="$profile_dir/run_$build_config"
    local artifact_dir="$directory/logs/artifacts/run_$build_config"
    local corpus_dir="${LIGHTTPD_FUZZ_CORPUS:-$directory/corpus}"
    mkdir -p "$config_profile_dir" "$artifact_dir"

    if [ ! -x "$binary" ] || [ ! -f "$config" ] || [ ! -f "$variant_config" ]; then
        echo "Configuration $build_config has not been built and staged."
        echo "Run ./build.sh --config=$build_config --directory first."
        return 1
    fi
    stop_previous "$pid_file" "$binary" "$config" || return 1
    archive_previous_error_log "$build_config" || return 1

    local profile_file="$config_profile_dir/default-%m-%p%c.profraw"
    # UBSan reports recoverable language errors and keeps fuzzing.  ASan stops
    # after an invalid memory access because continuing from corrupted process
    # state is unreliable and libFuzzer must retain the triggering input.
    local asan_options="strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1:symbolize=1:external_symbolizer_path=$LLVM_ROOT/bin/llvm-symbolizer:log_path=$directory/logs/asan$build_config.log:halt_on_error=1"
    local ubsan_options="print_stacktrace=1:halt_on_error=0:log_path=$directory/logs/asan$build_config.log"
    local command=("$binary" -D -f "$config" -m "$run_dir/lib")
    local run_environment=(
        "LIGHTTPD_FUZZ_PORT=$port"
        "LIGHTTPD_FUZZ_CORPUS=$corpus_dir"
        "LIGHTTPD_FUZZ_ARTIFACT_PREFIX=$artifact_dir/"
        "LLVM_PROFILE_FILE=$profile_file"
        "ASAN_OPTIONS=$asan_options"
        "UBSAN_OPTIONS=$ubsan_options"
        "LSAN_OPTIONS=detect_leaks=0"
    )
    if grep -Eq '^[[:space:]]*extforward\.hap-PROXY[[:space:]]*=[[:space:]]*"enable"' "$variant_config"; then
        run_environment+=("LIGHTTPD_FUZZ_HAP_PROXY=1")
    fi
    if [ "$TEST_CASE_LOG" -eq 1 ]; then
        run_environment+=("LIGHTTPD_FUZZ_LOG=$directory/logs/testCases$build_config")
    fi
    [ -n "$FUZZ" ] && command+=("$FUZZ")

    echo "Starting config $build_config on 127.0.0.1:$port"
    if [ "$LOG_OUTPUT" -eq 1 ]; then
        setsid env "${run_environment[@]}" "${command[@]}" >"$directory/logs/error$build_config" 2>&1 &
    else
        setsid env "${run_environment[@]}" "${command[@]}" &
    fi
    local pid="$!"
    fuzzer_pids+=("$pid")
    fuzzer_configs["$pid"]="$build_config"
    server_pid_files["$pid"]="$pid_file"
}

backend_enabled=0
if selected_configs_require_backend; then
    start_backend_responder || exit 1
    backend_enabled=1
fi

if [ "$PACKET_CAPTURE" -eq 1 ]; then
    if ! command -v tcpdump >/dev/null; then
        echo "tcpdump is required for --packet"
        exit 1
    fi
    tcpdump_filter="tcp and ("
    separator=""
    for build_config in "${selected_configs[@]}"; do
        config_number="$((10#$build_config))"
        tcpdump_filter+="${separator}port $((5600 + config_number))"
        separator=" or "
    done
    if [ "$backend_enabled" -eq 1 ]; then
        tcpdump_filter+="${separator}port 6501 or port 6502 or port 6503"
    fi
    tcpdump_filter+=")"
    setsid tcpdump -G 43200 -i lo -w "$directory/logs/dump$$-%Y%m%dT%H%M%S.pcap" "$tcpdump_filter" &
    capture_pids+=("$!")
fi

for build_config in "${selected_configs[@]}"; do
    run_fuzzer "$build_config" || exit
done

maintenance_ticks=0
while sleep 5; do
    for index in "${!backend_pids[@]}"; do
        pid="${backend_pids[$index]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            status="$?"
            unset "backend_pids[$index]"
            echo "Backend responder $pid exited with status $status; stopping this campaign."
            exit 1
        fi
    done
    for index in "${!fuzzer_pids[@]}"; do
        pid="${fuzzer_pids[$index]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            status="$?"
            config_id="${fuzzer_configs[$pid]}"
            pid_file="${server_pid_files[$pid]}"
            if [ -f "$pid_file" ] && [ "$(sed -n '1p' "$pid_file")" = "$pid" ]; then
                rm -f "$pid_file"
            fi
            unset "fuzzer_pids[$index]"
            unset "fuzzer_configs[$pid]"
            unset "server_pid_files[$pid]"
            echo "Config $config_id child $pid exited with status $status; ${#fuzzer_pids[@]} fuzzing profiles remain."
        fi
    done
    for index in "${!capture_pids[@]}"; do
        pid="${capture_pids[$index]}"
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid"
            status="$?"
            unset "capture_pids[$index]"
            echo "Packet-capture child $pid exited with status $status; fuzzing continues."
        fi
    done
    if [ "${#fuzzer_pids[@]}" -eq 0 ]; then
        echo "No fuzzing profiles remain."
        exit 1
    fi
    maintenance_ticks="$((maintenance_ticks + 1))"
    if [ "$maintenance_ticks" -ge 12 ]; then
        maintenance_ticks=0
        "$directory/asanProcess.sh"
        if command -v logrotate >/dev/null && [ -f "$directory/run/logrotate.conf" ]; then
            logrotate "$directory/run/logrotate.conf" -s "$directory/logs/old/logrotate.status"
        fi
    fi
done
