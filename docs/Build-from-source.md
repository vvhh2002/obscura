## Requirements

- Rust 1.75+ ([rustup.rs](https://rustup.rs))
- C compiler (gcc or clang)
- ~5 GB free disk space (V8 compiles from source on first build)

First build takes about 5 minutes. Incremental builds are seconds.

## Build

```bash
git clone https://github.com/h4ckf0r0day/obscura.git
cd obscura
cargo build --release -p obscura-cli --bins --features render
```

Binary is at `./target/release/obscura`.

This produces the release binary with geometry, screenshots, screencasting,
and PDF export.

Release artifacts are native binaries for their named target, not a promise of
fully static linkage. Linux packages currently target GNU/glibc, macOS binaries
use the platform system libraries/frameworks, and Windows packages target MSVC.
Use the matching supported operating-system/runtime baseline when distributing
them.

## Rendering and stealth

```bash
cargo build --release -p obscura-cli --bins --features render,stealth
```

This is the complete rendering build with the stealth wreq/BoringSSL transport,
TLS fingerprint randomization, browser-identity protections, and tracker
blocklist. See [Configure stealth and proxies](Configure-stealth-and-proxies.md).

## Without rendering

```bash
cargo build --release -p obscura-cli --bins --no-default-features
cargo build --release -p obscura-cli --bins --no-default-features --features stealth
```

The second command keeps stealth while excluding layout, screenshots,
screencasting, and PDF export.

## Vendored deno_core

The workspace patches crates.io `deno_core` to the pinned in-tree
`vendor/deno-core` copy. Obscura keeps version 0.350.0 and adds the smallest
managed-realm surface needed for independent iframe module maps, dynamic
imports, and event-loop polling. The upstream source record, archive digest,
local patch surface, and MIT license location are documented in
[`vendor/deno-core/OBSCURA-VENDORING.md`](../vendor/deno-core/OBSCURA-VENDORING.md).
No Git dependency or network checkout is required at runtime.
Module graphs use deno_core's own `RecursiveModuleLoad`; this workspace does
not add a `deno_graph` dependency.

CI and release jobs run `python3 scripts/ci/check_vendor_licenses.py`. The
check requires every in-tree crate to have a package/version/license-matched
provenance record, source-archive SHA-256, upstream HTTPS URL, license text,
and matching `[patch.crates-io]` path.

The stealth feature builds BoringSSL and generates Rust bindings. In addition
to the default requirements, install CMake, Clang, and the libclang/LLVM
development libraries. On Ubuntu/Debian:

```bash
sudo apt-get install build-essential cmake clang libclang-dev llvm-dev
```

On macOS, install the Xcode Command Line Tools and CMake. On Windows, install
the Visual Studio C++ Build Tools, CMake, and LLVM/Clang. Ensure the directory
containing `libclang` is available through `LIBCLANG_PATH` if bindgen cannot
locate it automatically.

On macOS 26 with the standalone Command Line Tools, Apple Clang may not find
libc++ while compiling BoringSSL. Use the active SDK for that build:

```bash
SDK_PATH="$(xcrun --show-sdk-path)"
SDKROOT="$SDK_PATH" CXXFLAGS="-isystem $SDK_PATH/usr/include/c++/v1" \
  cargo build --release -p obscura-cli --bins --features render,stealth
```

## OpenSSL on older systems

If the build fails on the vendored OpenSSL with an AVX-512 assembler error (common on older VPS hosts):

```bash
OPENSSL_NO_VENDOR=1 cargo build --release -p obscura-cli --bins --features render
```

Uses the system OpenSSL instead.

## Run from the build

```bash
./target/release/obscura --version
./target/release/obscura fetch https://example.com --eval "document.title"
```

Install system-wide:

```bash
cargo install --path crates/obscura-cli --features render
```

## Tests

```bash
cargo nextest run --release --features render --no-fail-fast
```

Integration suite:

```bash
python3 tests/test_all.py
```

Use `cargo nextest`, not `cargo test`: runtime tests require process isolation
because the engine owns a single V8 isolate per process.

## GitHub Actions CI

Pull requests continue to use `.github/workflows/ci.yml`, including the
base-revision policy and performance comparison. Its five interleaved samples
are compared by median; either latency or peak RSS strictly above `1.10x` the
base fails, with no additional absolute-delta exception. Pushes to `main` or
`VVDevelop` use `.github/workflows/ci-branch.yml`. The branch workflow can also
be started manually from the Actions tab and runs the release-mode render test
suite plus the render/stealth/no-render build configurations. It has read-only
repository permissions and receives no repository secrets.

GitHub only exposes a workflow's **Run workflow** button after that workflow
exists on the repository's default branch. When developing the workflow on a
different branch, merge it into the default branch first or make that branch
the default, then select the desired source branch in the workflow picker.

## Manual releases

`.github/workflows/release.yml` still runs automatically for a pushed `v*`
tag. It also supports `workflow_dispatch` for a guarded manual build:

1. Open **Actions → Release → Run workflow** and select the exact branch whose
   current commit should be released.
2. Enter a SemVer version such as `0.2.0` or `v0.2.0`. The workflow adds the
   leading `v` when it is omitted.
3. Select **build** to create downloadable workflow artifacts only, or
   **publish** to create or update a public GitHub Release after every build
   succeeds.

Manual publication creates a missing tag at the selected commit, generates
release notes for a new Release, and publishes a non-draft release. Updating an
existing Release preserves its notes; publishing an existing draft makes it
public. A pre-existing tag must already resolve to the selected commit. Tags
with a prerelease suffix, such as `v0.2.0-rc.1`, are marked as prereleases
automatically.

The prepare job resolves one immutable commit SHA. A release test gate checks
out and verifies that exact SHA, runs the focused document-loading regressions,
then runs the full render suite in release mode. The native platform matrix
does not start, and publication cannot run, unless both test stages pass. Every
native matrix build checks out the same SHA, and the tag without its leading
`v` is injected as the CLI version. Immediately before publication, the
workflow resolves the tag again (including annotated tags) and fails if it
moved while the matrix was building.
The matrix builds Linux x86_64/ARM64, macOS Apple Silicon/Intel, and Windows
x86_64. Each platform produces default, stealth, no-render, and
no-render-stealth archives, runs an offline V8 startup smoke test, and uploads
the packages for seven days. Published releases also contain `SHA256SUMS`.

Only the final publish job receives `contents: write`; it does not check out or
execute repository code. The build jobs remain read-only. A tag created by the
repository `GITHUB_TOKEN` does not start another workflow, so a tag created by
manual binary publication does not automatically run the separate Docker
workflow. When a Docker image is required too, create and push the tag through
the normal Git flow instead of using the manual **publish** mode; that tag push
starts both the binary Release and Docker workflows.
