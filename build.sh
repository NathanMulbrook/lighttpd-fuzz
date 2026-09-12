#!/usr/bin/env bash
set -euo pipefail

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

help() {
    echo "Usage: ./build.sh [options]"
    echo "  --bootstrap-toolchain  Build the pinned LLVM toolchain and exit"
    echo "  --config=N, -c=N       Build configuration N (default: all discovered configs)"
    echo "  --directory, -d        Create the server runtime directory"
    echo "  --rebuild-directory, -r  Recreate runtime files from an existing build"
    echo "  --jobs, -j             Build with ten jobs per configuration"
    echo "  --jobs=N, -j=N, -jN    Build with N jobs per configuration"
    echo "  --init, -i             Clone upstream lighttpd if it is missing"
    echo "  --no_patch, -p         Build without integration or known-finding patches"
}

for arg in "$@"; do
    case "$arg" in
    --help | -h)
        help
        exit
        ;;
    --bootstrap-toolchain)
        "$directory/toolchain/build-llvm.sh"
        exit
        ;;
    esac
done

source "$directory/toolchain/use-llvm.sh"

PATCH=1
CONFIG="all"
BUILD_INIT=0
BUILD_DIRECTORY=0
REBUILD_DIRECTORY=0
JOBS=1
LIGHTTPD_REF="${LIGHTTPD_REF:-2ddc51389a139d2b08daf310596c951c1d53dc8d}"
LIGHTTPD_REPOSITORY="${LIGHTTPD_REPOSITORY:-https://github.com/lighttpd/lighttpd1.4.git}"
source_dir="$directory/lighttpd"
PATCHDIRS=(
    "lighttpd-patches/patches"
    "lighttpd-patches-private/findings"
)

CONFIG_IDS=()

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

for arg in "$@"; do
    case "$arg" in
    --directory | -d)
        BUILD_DIRECTORY=1
        ;;
    --rebuild-directory | -r)
        REBUILD_DIRECTORY=1
        BUILD_DIRECTORY=1
        ;;
    --init | -i)
        BUILD_INIT=1
        ;;
    --jobs | -j)
        JOBS=10
        ;;
    --jobs=* | -j=*)
        JOBS="${arg#*=}"
        ;;
    -j[0-9]*)
        JOBS="${arg#-j}"
        ;;
    --no_patch | --no-patch | -p)
        PATCH=0
        ;;
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    esac
done

if [[ ! "$JOBS" =~ ^[0-9]{1,5}$ ]]; then
    echo "Build job count must be a positive integer."
    exit 1
fi
JOBS="$((10#$JOBS))"
if [ "$JOBS" -eq 0 ]; then
    echo "Build job count must be a positive integer."
    exit 1
fi

discover_configs || exit 1
if [ "$CONFIG" != "a" ] && [ "$CONFIG" != "all" ] && ! valid_config "$CONFIG"; then
    echo "Build configuration '$CONFIG' is not available."
    echo "Available configurations: ${CONFIG_IDS[*]}"
    exit 1
fi

if [ "$BUILD_INIT" -eq 1 ] && [ ! -d "$source_dir/.git" ]; then
    git clone "$LIGHTTPD_REPOSITORY" "$source_dir"
fi
if [ ! -d "$source_dir/.git" ]; then
    echo "Missing upstream source at $source_dir"
    echo "Run ./build.sh --init or clone lighttpd there."
    exit 1
fi
if ! git -C "$source_dir" cat-file -e "$LIGHTTPD_REF^{commit}" 2>/dev/null; then
    echo "lighttpd ref is not available locally: $LIGHTTPD_REF"
    exit 1
fi

# Keep recoverable UBSan checks running after they are reported.  Memory-safety
# failures remain terminal under the ASan runtime policy in run.sh.
export CFLAGS="-g -O1 -pipe -Wall -fno-omit-frame-pointer -fno-common -fstack-protector-all -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -fsanitize-recover=all -fsanitize=fuzzer-no-link,address,undefined -fprofile-instr-generate -fcoverage-mapping -mllvm -runtime-counter-relocation"
export CPPFLAGS="-U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0"
export LDFLAGS="-fuse-ld=lld -Wl,--threads=1 -fsanitize-recover=all -fsanitize=fuzzer-no-link,address,undefined -fprofile-instr-generate -fcoverage-mapping"
export CC_FOR_BUILD="$CC"
export CFLAGS_FOR_BUILD="-O2"
export ASAN_OPTIONS="detect_leaks=0"
export LSAN_OPTIONS="detect_leaks=0"

config_build() {
    config_flags=(
        --disable-dependency-tracking
        --with-pcre2
        --with-zlib
        --with-zstd
        --with-bzip2
        --with-brotli
    )
}

stop_instance() {
    local build_config="$1"
    local run_dir="$directory/run/run_$build_config"
    local pid_file="$run_dir/lighttpd.pid"
    local binary="$run_dir/sbin/lighttpd"
    local config="$run_dir/config/lighttpd.conf"
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
        echo "Ignoring stale PID file for config $build_config: $pid"
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
        kill -0 "$pid" 2>/dev/null || break
        sleep 0.1
    done
    if kill -0 "$pid" 2>/dev/null; then
        echo "Running lighttpd process $pid did not stop."
        return 1
    fi
}

render_template() {
    local input="$1"
    local output="$2"
    local run_dir="$3"
    local port="$4"
    sed -e "s|@RUN_DIR@|$run_dir|g" -e "s|@PORT@|$port|g" "$input" >"$output"
}

stage_runtime() {
    local build_config="$1"
    local run_dir="$directory/run/run_$build_config"
    local config_number="$((10#$build_config))"
    local port="$((5600 + config_number))"

    if [ ! -x "$run_dir/sbin/lighttpd" ]; then
        echo "Missing installed lighttpd for config $build_config"
        return 1
    fi

    rm -rf "$run_dir/config" "$run_dir/www" "$run_dir/tmp"
    mkdir -p "$run_dir/config" "$run_dir/www" "$run_dir/tmp/uploads" "$run_dir/tmp/cache/compress" "$run_dir/tmp/dav"
    cp -a "$directory/configs/docroot/." "$run_dir/www/"
    ln -s "$run_dir/www/files/index.txt" "$run_dir/tmp/dav/static-link.txt"
    cp "$directory/configs/users" "$run_dir/config/users"
    render_template "$directory/configs/common.conf.in" "$run_dir/config/lighttpd.conf" "$run_dir" "$port"
    render_template "$directory/configs/config-$build_config.conf.in" "$run_dir/config/variant.conf" "$run_dir" "$port"
    printf '\ninclude "%s"\n' "$run_dir/config/variant.conf" >>"$run_dir/config/lighttpd.conf"
    mkdir -p "$directory/run"
    sed "s|@ROOT@|$directory|g" "$directory/logrotate.conf" >"$directory/run/logrotate.conf"

    "$run_dir/sbin/lighttpd" -D -tt -f "$run_dir/config/lighttpd.conf" -m "$run_dir/lib"
    mkdir -p "$directory/corpus"
    "$directory/normalize-corpus-flags.py" --seeds-only "$directory/corpus"
}

apply_patches() {
    local temp_source_dir="$1"
    [ "$PATCH" -eq 1 ] || return 0
    if [ ! -f "$directory/lighttpd-patches/patches/fuzzer.patch" ]; then
        echo "Missing required integration patch: lighttpd-patches/patches/fuzzer.patch"
        return 1
    fi
    local patch_dir patch_file
    local applied=0
    for patch_dir in "${PATCHDIRS[@]}"; do
        [ -d "$directory/$patch_dir" ] || continue
        while IFS= read -r -d '' patch_file; do
            (
                cd "$temp_source_dir"
                patch --batch --forward --fuzz=0 --strip=1 --input="$patch_file"
            )
            applied=1
        done < <(find "$directory/$patch_dir" -mindepth 1 -maxdepth 2 -type f -name '*.patch' -print0 | sort -z)
    done
    if [ "$applied" -eq 0 ]; then
        echo "No build-time patches found; refusing to build an unintegrated fuzzer."
        return 1
    fi
}

build_software() {
    local build_config="$1"
    valid_config "$build_config" || {
        echo "Build configuration '$build_config' is not available."
        echo "Available configurations: ${CONFIG_IDS[*]}"
        return 1
    }

    local run_dir="$directory/run/run_$build_config"
    local build_dir="$directory/build/build_$build_config"
    local temp_source_dir="$directory/build/src_$build_config"

    stop_instance "$build_config"
    if [ "$REBUILD_DIRECTORY" -eq 1 ]; then
        stage_runtime "$build_config"
        return
    fi

    rm -rf "$build_dir" "$temp_source_dir" "$run_dir"
    mkdir -p "$build_dir" "$temp_source_dir" "$run_dir" "$directory/logs"

    git -C "$source_dir" archive "$LIGHTTPD_REF" | tar -x -C "$temp_source_dir"
    apply_patches "$temp_source_dir"
    cp "$directory/fuzzer.c" "$directory/fuzzer.h" "$temp_source_dir/src/"

    (
        cd "$temp_source_dir"
        ./autogen.sh
    )

    config_build
    (
        cd "$build_dir"
        "$temp_source_dir/configure" "${config_flags[@]}" --prefix="$run_dir" --sbindir="$run_dir/sbin" --libdir="$run_dir/lib"
        make -j "$JOBS"
        make install
    )

    if [ "$BUILD_DIRECTORY" -eq 1 ]; then
        stage_runtime "$build_config"
    fi
}

mkdir -p "$directory/logs"
if [ "$CONFIG" = "a" ] || [ "$CONFIG" = "all" ]; then
    child_args=()
    if [ "$REBUILD_DIRECTORY" -eq 1 ]; then
        child_args+=(--rebuild-directory)
    elif [ "$BUILD_DIRECTORY" -eq 1 ]; then
        child_args+=(--directory)
    fi
    [ "$JOBS" -gt 1 ] && child_args+=("--jobs=$JOBS")
    [ "$PATCH" -eq 0 ] && child_args+=(--no_patch)

    if ! command -v setsid >/dev/null; then
        echo "setsid is required to isolate parallel build children."
        exit 1
    fi

    available_cores="$(nproc 2>/dev/null || echo 1)"
    if [[ ! "$available_cores" =~ ^[1-9][0-9]{0,8}$ ]]; then
        available_cores=1
    else
        available_cores="$((10#$available_cores))"
    fi
    max_config_builds="$((available_cores / JOBS))"
    [ "$max_config_builds" -lt 1 ] && max_config_builds=1
    [ "$max_config_builds" -gt "${#CONFIG_IDS[@]}" ] && max_config_builds="${#CONFIG_IDS[@]}"
    echo "Building up to $max_config_builds configurations concurrently ($JOBS make jobs each; $available_cores cores detected)."

    declare -A build_children=()
    cleanup_build_children() {
        local pid running
        trap - EXIT INT TERM
        for pid in "${!build_children[@]}"; do
            kill -TERM -- "-$pid" 2>/dev/null || true
        done
        for _ in {1..100}; do
            running=0
            for pid in "${!build_children[@]}"; do
                kill -0 -- "-$pid" 2>/dev/null && running=1
            done
            [ "$running" -eq 0 ] && break
            sleep 0.1
        done
        for pid in "${!build_children[@]}"; do
            if kill -0 -- "-$pid" 2>/dev/null; then
                echo "Forcing configuration build ${build_children[$pid]} to stop after 10 seconds." >&2
                kill -KILL -- "-$pid" 2>/dev/null || true
            fi
        done
        for pid in "${!build_children[@]}"; do
            wait "$pid" 2>/dev/null || true
        done
    }
    trap cleanup_build_children EXIT
    trap 'cleanup_build_children; exit 130' INT
    trap 'cleanup_build_children; exit 143' TERM

    next_config=0
    result=0
    while [ "$next_config" -lt "${#CONFIG_IDS[@]}" ] || [ "${#build_children[@]}" -gt 0 ]; do
        while [ "$next_config" -lt "${#CONFIG_IDS[@]}" ] && [ "${#build_children[@]}" -lt "$max_config_builds" ]; do
            build_config="${CONFIG_IDS[$next_config]}"
            setsid "$0" "--config=$build_config" "${child_args[@]}" > >(tee "$directory/logs/build$build_config.log") 2>&1 &
            build_children["$!"]="$build_config"
            next_config="$((next_config + 1))"
        done

        completed_pid=""
        if wait -n -p completed_pid "${!build_children[@]}"; then
            :
        else
            result=1
        fi
        [ -n "$completed_pid" ] && unset 'build_children[$completed_pid]'
        if [ "$result" -ne 0 ]; then
            echo "A configuration build failed; stopping the remaining parallel builds." >&2
            exit "$result"
        fi
    done
    trap - EXIT INT TERM
    exit 0
fi

build_software "$CONFIG"
