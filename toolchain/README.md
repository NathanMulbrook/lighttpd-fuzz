# LLVM toolchain

The fuzzer build uses a local LLVM 23.1.1 toolchain so Clang, ASan, UBSan,
libFuzzer, and the coverage tools all come from the same release. The source
archive is pinned by SHA-256 and downloaded from the official LLVM release.

Build the toolchain once:

```console
./build.sh --bootstrap-toolchain
```

The build needs at least 80 GB free and installs under
`toolchain/llvm-23.1.1`. Sources and intermediate files remain under
`toolchain/work`, allowing an interrupted build to resume. That work
directory can be removed after installation.

The bootstrap inherits the host Clang target and system configuration. Normal
builds select Clang, llvm-ar, llvm-nm, llvm-ranlib, llvm-cov, llvm-profdata, and
llvm-symbolizer from the local installation.

Optional environment variables:

- `LLVM_TOOLCHAIN_WORK_DIR` moves sources and intermediate build files.
- `LLVM_TOOLCHAIN_JOBS` controls parallel compilation.
- `LLVM_ROOT` selects another complete LLVM 23.1.1 installation.
- `LLVM_MIN_FREE_GB` changes the free-space safety check.
