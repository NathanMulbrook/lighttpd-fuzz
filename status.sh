#!/usr/bin/env bash
set -u

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
CONFIG="all"

for arg in "$@"; do
    case "$arg" in
    --config=* | -c=*)
        CONFIG="${arg#*=}"
        ;;
    --help | -h)
        echo "Usage: ./status.sh [--config=N|all]"
        exit 0
        ;;
    *)
        echo "Unknown argument: $arg" >&2
        exit 1
        ;;
    esac
done

config_ids=()
while IFS= read -r config_path; do
    filename="${config_path##*/}"
    config_id="${filename#config-}"
    config_ids+=("${config_id%.conf.in}")
done < <(find "$directory/configs" -maxdepth 1 -type f -name 'config-[0-9]*.conf.in' -print | sort -V)

if [ "$CONFIG" != "all" ] && [ "$CONFIG" != "a" ]; then
    found=0
    for config_id in "${config_ids[@]}"; do
        if [ "$config_id" = "$CONFIG" ]; then
            config_ids=("$config_id")
            found=1
            break
        fi
    done
    if [ "$found" -eq 0 ]; then
        echo "Configuration '$CONFIG' is not available." >&2
        exit 1
    fi
fi

read -r corpus_files corpus_latest < <(
    find "$directory/corpus" -maxdepth 1 -type f -printf '%T@\n' |
        awk '{ count++; if ($1 > latest) latest=$1 } END { printf "%d %.0f\n", count, latest }'
)
corpus_size="$(du -sh "$directory/corpus" | awk '{print $1}')"
now="$(date +%s)"
if [ "$corpus_latest" -gt 0 ]; then
    corpus_age="$((now - corpus_latest))"
else
    corpus_age=0
fi

fuzzing=0
server_only=0
stopped=0
lines=()

for config_id in "${config_ids[@]}"; do
    run_dir="$directory/run/run_$config_id"
    pid_file="$run_dir/lighttpd.pid"
    state="stopped"
    detail=""

    if [ -f "$pid_file" ]; then
        read -r pid < "$pid_file"
        case "$pid" in
        '' | *[!0-9]*) pid="" ;;
        esac
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            expected_exe="$(realpath -m "$run_dir/sbin/lighttpd")"
            actual_exe="$(readlink "/proc/$pid/exe" 2>/dev/null || true)"
            actual_exe="${actual_exe% (deleted)}"
            if [ "$actual_exe" = "$expected_exe" ]; then
                if tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null | grep -Fqx -- '-F'; then
                    state="fuzzing"
                    fuzzing="$((fuzzing + 1))"
                else
                    state="server-only"
                    server_only="$((server_only + 1))"
                fi
                cpu="$(ps -p "$pid" -o %cpu= | awk 'NR == 1 { print $1 }')"
                detail="pid=$pid cpu=${cpu:-?}%"
            fi
        fi
    fi

    if [ "$state" = "stopped" ]; then
        stopped="$((stopped + 1))"
    elif [ "$state" = "fuzzing" ] && [ -f "$directory/logs/error$config_id" ]; then
        progress="$(grep -aE '^#[0-9]+.*(pulse|INITED|NEW|REDUCE)' "$directory/logs/error$config_id" | tail -n 1 || true)"
        if [ -n "$progress" ]; then
            detail+=" ${progress:0:180}"
        else
            detail+=" starting"
        fi
    fi
    lines+=("$(printf 'config %2d  %-11s %s' "$config_id" "$state" "$detail")")
done

echo "Profiles: $fuzzing fuzzing, $server_only server-only, $stopped stopped"
echo "Corpus: $corpus_files files, $corpus_size, newest file ${corpus_age}s ago"
printf '%s\n' "${lines[@]}"
