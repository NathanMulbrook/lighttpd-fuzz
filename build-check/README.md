# Build artifact checker

This directory is copied from the 389 DS fuzzing project. The standalone Python
checker inspects Linux ELF object files, archives, executables, and shared
libraries without executing them. It requires Python 3.9+ and GNU binutils.

From the repository root:

```console
./checkObjects.sh
./checkObjects.sh /path/to/another.ini
```

The lighttpd configuration scans every build and install tree under the matrix
roots, so newly added numeric configurations are covered automatically. It
excludes exported source trees and runtime config, share, document-root, and
temporary directories. It expects
stack protection, ASan, UBSan, libFuzzer guidance, SanitizerCoverage comparison
and PC-table feedback, LLVM profiles, and source coverage. It expects Fortify,
TSan, and MSan to be absent. The final lighttpd executable must contain
`LLVMFuzzerRunDriver`; ordinary objects and modules do not need the driver.

The combined Markdown report is written to `logs/symbolReport.md`. Exit status
is 0 for success, 1 for an expectation failure, and 2 for configuration,
discovery, inspection, or report-write errors.

## Configuration

Paths in `check-build.ini` are relative to that file. `object_dirs` scans
recursively for relocatable ELF files and archives. `binary_paths` accepts
individual ELF files or recursively scanned directories. `exclude` entries
use shell-style patterns.

Each check can be `present`, `absent`, or `ignore`. Later
`[checks:PATH_GLOB]` sections override individual expectations for matching
paths. This is useful for tiny translation units that contain no eligible
comparison or undefined operation, and for final linked executables where
compiler runtime definitions can make a symbol-only check inconclusive.

The checker reports evidence for:

- `stack_protector`: stack guard/failure references
- `fortify`: glibc fortified call references
- `asan`, `ubsan`, `tsan`, and `msan`: sanitizer hooks/sections
- `sancov`: SanitizerCoverage callbacks, guards, counters, or flags
- `sancov_cmp`: comparison/switch callbacks
- `sancov_pc_table`: PC table or initialization references
- `llvm_profile`: LLVM profile counter/bitmap sections
- `source_coverage`: LLVM source coverage mapping sections
- `libfuzzer`: the `LLVMFuzzerRunDriver` definition/reference

`FOUND` means direct section or strong-reference evidence was present.
`SYMBOL-ONLY` and `UNKNOWN` are inconclusive. `NOT-SEEN` means the
available ELF tables did not contain matching evidence.

Run the checker tests from this directory:

```console
python3 -m unittest -v test_check_build.py
```
