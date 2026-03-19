# Building an ASAN-Enabled OpenHCL IGVM

This guide explains how to build an OpenHCL IGVM image with [AddressSanitizer (ASAN)](https://clang.llvm.org/docs/AddressSanitizer.html) instrumentation enabled. This is useful for debugging memory corruption bugs (use-after-free, heap-buffer-overflow, stack-buffer-overflow, etc.) in the OpenHCL underhill environment.

## How ASAN support works

ASAN support is implemented via the `sanitizer` cargo feature and a dedicated IGVM recipe (`X64Asan`). The following components are involved:

| Component | What it does |
|-----------|-------------|
| `openhcl/underhill_entry/Cargo.toml` | Defines the `sanitizer` feature; makes `mimalloc` and `fast_memcpy` optional |
| `openhcl/underhill_entry/src/lib.rs` | Gates out mimalloc global allocator and fast_memcpy when `sanitizer` is active |
| `openhcl/openvmm_hcl/Cargo.toml` | Forwards `sanitizer` feature to `underhill_entry` |
| `vm/loader/manifests/openhcl-x64-asan.json` | Sets `memory_page_count` to 524288 (2 GB) for ASAN overhead |
| `openhcl/rootfs.asan.config` | Adds musl shared libraries (libc.so, libgcc_s.so.1, ld-musl symlink) |

### Why these changes are needed

- **mimalloc disabled**: ASAN needs to intercept all allocations via its own instrumented allocator. If mimalloc is the `#[global_allocator]`, ASAN cannot track heap operations. With the `sanitizer` feature, the default musl malloc is used instead, which ASAN can intercept.

- **fast_memcpy disabled**: ASAN needs to intercept `memcpy`/`memset`/`memmove` to detect buffer overflows. The `fast_memcpy` crate replaces the system `memcpy`, bypassing ASAN's interceptors.

- **Dynamic linking (`-crt-static` removed)**: ASAN requires the binary to be dynamically linked so the sanitizer runtime can be loaded. This means the resulting binary depends on `libc.so`, `libgcc_s.so.1`, and the musl dynamic linker — which must be added to the IGVM rootfs.

- **Memory increased to 2 GB**: ASAN's shadow memory and metadata add significant overhead. The default 512 MB (`memory_page_count: 131072`) is not enough; 2 GB (`memory_page_count: 524288`) is needed to avoid initramfs unpacking failures.

---

## Building with flowey (recommended)

The easiest way to build an ASAN-enabled IGVM is to use the `X64Asan` recipe via `cargo xflowey build-igvm`:

```bash
cargo xflowey build-igvm x64-asan
```

This handles all RUSTFLAGS, feature flags, sysroot configuration, and rootfs shared library inclusion automatically.

The output IGVM will be at:

```
flowey-out/artifacts/build-igvm/debug/x64-asan/openhcl-x64-asan.bin
```

### CI

The `X64Asan` recipe is built automatically in the CI (nightly) pipeline alongside other x64 IGVM recipes. ASAN VMM tests run only in CI, not in PR builds.

---

## Manual build (x86_64)

If you need to build manually (e.g., with a custom openvmm_hcl binary), follow these steps.

### Prerequisites

- Rust stable toolchain with `x86_64-unknown-linux-musl` target
- The repo's sysroot packages restored (`cargo xflowey` / repo setup)
- The `RUSTC_BOOTSTRAP=1` env var (needed for `-Zsanitizer=address` on stable)

### Step 1: Build the ASAN binary

```bash
cd openhcl/openvmm_hcl

RUSTFLAGS="-Zsanitizer=address \
  -Cforce-unwind-tables=yes \
  -Ctarget-feature=-crt-static \
  -Clink-self-contained=n \
  -Cforce-frame-pointers=yes \
  -Csymbol-mangling-version=v0 \
  -Clink-arg=-Wl,-z,pack-relative-relocs" \
RUSTC_BOOTSTRAP=1 \
cargo build --features sanitizer --target x86_64-unknown-linux-musl
```

```admonish note
You must run `cargo build` from the `openhcl/openvmm_hcl` directory (not the repo root), because `--features` cannot be used with `-p <package>` for packages outside the current workspace.
```

The binary will be at:

```
target/x86_64-unknown-linux-musl/debug/openvmm_hcl
```

### Step 2: Build the IGVM

```bash
OPENHCL_SYSROOT_LIB=.packages/extracted/x86_64-sysroot/lib \
cargo xflowey build-igvm x64 \
  --custom-openvmm-hcl target/x86_64-unknown-linux-musl/debug/openvmm_hcl
```

The `OPENHCL_SYSROOT_LIB` environment variable tells the rootfs builder where to find the musl shared libraries (`libc.so`, `libgcc_s.so.1`) that the dynamically-linked ASAN binary needs.

### Step 3: Use the IGVM

Pass the resulting IGVM to your VM configuration in place of the standard OpenHCL IGVM. ASAN diagnostics will be printed to the serial console (com3 by default in the dev manifest).

---

## Rootfs shared library note

The `rootfs.asan.config` (included automatically by the `X64Asan` recipe) contains entries for the musl shared libraries needed by the dynamically-linked ASAN binary:

```
file /lib/libc.so              ${OPENHCL_SYSROOT_LIB}/libc.so          0755 0 0
file /lib/libgcc_s.so.1        ${OPENHCL_SYSROOT_LIB}/libgcc_s.so.1    0755 0 0
slink /lib/ld-musl-x86_64.so.1 /lib/libc.so 0755 0 0
```

When building manually, `OPENHCL_SYSROOT_LIB` must point to `.packages/extracted/x86_64-sysroot/lib`. The flowey `build-igvm x64-asan` recipe sets this automatically.

---

## Troubleshooting

### "Initramfs unpacking failed"

The VTL2 memory allocation is too small. Ensure the manifest's `memory_page_count` is set to at least `524288` (2 GB). The ASAN recipe uses `vm/loader/manifests/openhcl-x64-asan.json` which has this pre-configured.

### "Failed to execute /underhill-init (error -2)"

The ASAN binary is dynamically linked but the rootfs is missing the required shared libraries. Make sure:

1. `OPENHCL_SYSROOT_LIB` is set to the correct sysroot lib directory when building the IGVM.
2. The `rootfs.asan.config` entries for `libc.so`, `libgcc_s.so.1`, and the `ld-musl` symlink are present.

### "cannot find native static library `rustc-stable_rt.asan`"

The ASAN sanitizer runtime is not available for the target. This happens when cross-compiling. Rust only ships ASAN runtimes for the host architecture. Build on a native x86_64 Linux host.

### "cannot specify features for packages outside of workspace"

Run `cargo build` from the `openhcl/openvmm_hcl` directory, not the repo root. The `--features` flag doesn't work with `-p` for packages in different workspace roots.

---

## RUSTFLAGS reference

| Flag | Purpose |
|------|---------|
| `-Zsanitizer=address` | Enable AddressSanitizer instrumentation |
| `-Cforce-unwind-tables=yes` | Required for ASAN stack traces |
| `-Ctarget-feature=-crt-static` | Dynamically link musl (required for ASAN) |
| `-Clink-self-contained=n` | Use the sysroot musl, not Rust's bundled copy |
| `-Cforce-frame-pointers=yes` | Better stack traces (repo default) |
| `-Csymbol-mangling-version=v0` | Better symbol names in diagnostics (repo default) |
| `-Clink-arg=-Wl,-z,pack-relative-relocs` | Smaller relocations (x86_64 only) |

The `RUSTC_BOOTSTRAP=1` environment variable is required because `-Zsanitizer=address` is a nightly-only flag and we are using a stable toolchain.
