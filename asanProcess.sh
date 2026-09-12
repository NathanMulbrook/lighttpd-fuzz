#!/usr/bin/env bash

directory="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd "$directory"

mkdir -p logs/oldasan
if [ -f asanfiltered.log ]; then
    cp asanfiltered.log logs/oldasan/
fi
rm -f asanfiltered.log
touch asanfiltered.log

shopt -s nullglob
asan_candidates=(logs/asan*)
asan_logs=()
for file in "${asan_candidates[@]}"; do
    [ -f "$file" ] && asan_logs+=("$file")
done
error_logs=(logs/error*)
asan_error_count=0
libfuzzer_count=0
if [ "${#error_logs[@]}" -gt 0 ]; then
    asan_error_count="$(grep -hE 'ERROR: AddressSanitizer|AddressSanitizer: CHECK failed|AddressSanitizer:DEADLYSIGNAL' "${error_logs[@]}" 2>/dev/null | sort -u | wc -l)"
    libfuzzer_count="$(grep -hE 'ERROR: libFuzzer' "${error_logs[@]}" 2>/dev/null | sort -u | wc -l)"
fi
if [ "${#asan_logs[@]}" -eq 0 ]; then
    echo "AddressSanitizer: $asan_error_count"
    echo "Warnings: 0"
    echo "UBSan: 0"
    echo "libFuzzer: $libfuzzer_count"
    exit
fi

grep -h -v "SUMMARY: UndefinedBehaviorSanitizer: undefined-behavior " "${asan_logs[@]}" |
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
