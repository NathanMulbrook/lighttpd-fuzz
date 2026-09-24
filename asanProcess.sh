#!/usr/bin/env bash

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$directory"

rm -f asanfiltered.log
touch asanfiltered.log

shopt -s nullglob
asan_candidates=(logs/asan*)
asan_logs=()
asan_report_logs=()
declare -A harness_shutdown_candidates=()
declare -A report_candidate_identities=()
declare -A confirmed_shutdowns=()
harness_shutdown_count=0
for file in "${asan_candidates[@]}"; do
    [ -f "$file" ] || continue
    filename="${file##*/}"
    if [[ "$filename" =~ ^asan([0-9]+)\.log\.([0-9]+)$ ]]; then
        config_id="${BASH_REMATCH[1]}"
        report_pid="${BASH_REMATCH[2]}"
        supervisor_record=""
    elif [[ "$filename" =~ ^asan([0-9]+)\.log\.([A-Za-z0-9_-]+)\.([0-9]+)$ ]]; then
        config_id="${BASH_REMATCH[1]}"
        launch_id="${BASH_REMATCH[2]}"
        report_pid="${BASH_REMATCH[3]}"
        supervisor_record="$file.supervisor-stop"
    else
        continue
    fi
    asan_logs+=("$file")
    candidate_identity=""
    if [ -n "$config_id" ] \
        && [ -f "$supervisor_record" ] \
        && grep -Eq '^status=(72|137)$' "$supervisor_record" \
        && grep -Fq 'AddressSanitizer: CHECK failed: asan_report.cpp:227' "$file" \
        && grep -Fq 'fuzzer::Fuzzer::ExitCallback' "$file" \
        && ! grep -Eq 'ERROR: AddressSanitizer|AddressSanitizer:DEADLYSIGNAL' "$file"; then
        candidate_identity="$config_id:$launch_id:$report_pid"
        harness_shutdown_candidates["$candidate_identity"]=1
    fi
    report_candidate_identities["$file"]="$candidate_identity"
done
error_logs=(logs/error*)
asan_error_count=0
libfuzzer_count=0
error_scan=""
if [ "${#error_logs[@]}" -gt 0 ]; then
    error_scan="$({
        for file in "${error_logs[@]}"; do
            [ -f "$file" ] || continue
            filename="${file##*/}"
            if [[ "$filename" =~ ^error([0-9]+)$ ]]; then
                config_id="${BASH_REMATCH[1]}"
            else
                config_id=""
            fi
            shutdown_launch_pids=""
            if [ -n "$config_id" ]; then
                for key in "${!harness_shutdown_candidates[@]}"; do
                    if [[ "$key" == "$config_id:"* ]]; then
                        shutdown_launch_pids+=" ${key#*:}"
                    fi
                done
            fi
            awk -v config_id="$config_id" \
                -v shutdown_launch_pids="$shutdown_launch_pids" '
                BEGIN {
                    count = split(shutdown_launch_pids, values, " ")
                    for (i = 1; i <= count; ++i) {
                        if (values[i] == "") continue
                        split(values[i], identity, ":")
                        shutdown[identity[1], identity[2]] = 1
                    }
                }
                match($0, /^--- supervisor launch ([A-Za-z0-9_-]+) ---$/, fields) {
                    launch_id = fields[1]
                    suppress_shutdown_tail = 0
                    next
                }
                match($0, /^==([0-9]+)== ERROR: libFuzzer: fuzz target exited$/, fields) {
                    if (shutdown[launch_id, fields[1]]) {
                        print "@@HARNESS_SHUTDOWN@@ " config_id ":" launch_id ":" fields[1]
                        suppress_shutdown_tail = 1
                        next
                    }
                }
                suppress_shutdown_tail && /^AddressSanitizer:DEADLYSIGNAL$/ { next }
                suppress_shutdown_tail && /^SUMMARY: libFuzzer: fuzz target exited$/ {
                    suppress_shutdown_tail = 0
                    next
                }
                { suppress_shutdown_tail = 0 }
                /ERROR: AddressSanitizer|AddressSanitizer: CHECK failed|AddressSanitizer:DEADLYSIGNAL|ERROR: libFuzzer/ { print }
            ' "$file"
        done
    })"
    while read -r marker identity; do
        [ "$marker" = "@@HARNESS_SHUTDOWN@@" ] || continue
        confirmed_shutdowns["$identity"]=1
    done <<<"$error_scan"
    error_findings="$(grep -v '^@@HARNESS_SHUTDOWN@@ ' <<<"$error_scan" | sort -u)"
    asan_error_count="$(grep -Ec 'ERROR: AddressSanitizer|AddressSanitizer: CHECK failed|AddressSanitizer:DEADLYSIGNAL' <<<"$error_findings" || true)"
    libfuzzer_count="$(grep -Ec 'ERROR: libFuzzer' <<<"$error_findings" || true)"
fi
for file in "${asan_logs[@]}"; do
    candidate_identity="${report_candidate_identities[$file]:-}"
    if [ -n "$candidate_identity" ] \
        && [ -n "${confirmed_shutdowns[$candidate_identity]:-}" ]; then
        harness_shutdown_count="$((harness_shutdown_count + 1))"
    else
        asan_report_logs+=("$file")
    fi
done
if [ "${#asan_logs[@]}" -eq 0 ]; then
    echo "AddressSanitizer: $asan_error_count"
    echo "Warnings: 0"
    echo "UBSan: 0"
    echo "libFuzzer: $libfuzzer_count"
    echo "Harness shutdown: 0"
    exit
fi

if [ "${#asan_report_logs[@]}" -gt 0 ]; then
grep -h -v "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior " "${asan_report_logs[@]}" |
grep -v ": runtime error: " |
grep -v ": note: pointer points here" |
grep -v "note: nonnull attribute specified here" |
grep -E -v '(.{1,2}[0-9a-f]{2,2}){32}' |
grep -E -v '\s{1,100}\^\s' |
sed -E ':a;N;$!ba;s/\n/####/g' |
sed -E 's/(0x)[0]{12}/null/g' |
sed -E 's/(==)[0-9]{3,}(==)/==????==/g' |
sed -E 's/(0x)[0-9a-fA-F]{3,}/????/g' |
sed -E 's/([Tt]hread T)[0-9]{1,3}/thread T???/g' |
sed -E 's/(src_)[0-9]+/src_?/g' |
sed -E 's/(run_)[0-9]+/run_?/g' |
sed -E 's/\(BuildId: [0-9a-f]{15,40}\)/\(BuildId\: ?????????????\)/g' |
sed 's/####=================================================================/\n=================================================================/g' |
sed -E 's/#{3,12}/####/g' |
sort -u --parallel=6 |
sed 's/####/\n/g' >>asanfiltered.log
fi

grep -h ": runtime error: " "${asan_logs[@]}" |
sed -E 's/(0x)[0]{12}/null/g' |
sed -E 's/(0x)[0-9a-fA-F]{3,}/????/g' |
sed -E 's/(src_)[0-9]+/src_?/g' |
sed -E 's/(run_)[0-9]+/run_?/g' |
sort -u --parallel=6 >>asanfiltered.log

asan_count="$(grep -Ec 'ERROR: AddressSanitizer|AddressSanitizer: CHECK failed|AddressSanitizer:DEADLYSIGNAL' asanfiltered.log || true)"
asan_count="$((asan_count + asan_error_count))"
echo "AddressSanitizer: $asan_count"
printf "Warnings: "
grep -c "WARNING" asanfiltered.log || true
printf "UBSan: "
grep -c ": runtime error: " asanfiltered.log || true
echo "libFuzzer: $libfuzzer_count"
echo "Harness shutdown: $harness_shutdown_count"
