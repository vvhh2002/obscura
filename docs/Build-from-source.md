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

Before running it, create the protected GitHub Actions environment
`ai-slide-matcher-release` and add its environment secret
`AI_SLIDE_MATCHER_READ_TOKEN`. Restrict deployment branches/tags to the trusted
release refs and require reviewer approval. The secret must be a fine-grained
token (or equivalent short-lived GitHub App installation token exposed under
that secret name) with only **Contents: Read** access to
`vvhh2002/ai_slide_matcher`. Do not make it a repository-wide secret: manual
workflows can select a branch, so an environment boundary is required to stop
an unreviewed workflow revision from reading private matcher source. The
ordinary Obscura `GITHUB_TOKEN` is intentionally scoped to Obscura and cannot
read the private matcher repository. The checkout action receives this
credential with `persist-credentials: false`; build, test, packaging, and
publish commands do not receive it.

The workflow pins matcher source with the full `AI_SLIDE_MATCHER_REF` commit,
pairs it with a stable positive `AI_SLIDE_MATCHER_BUILD_NUMBER`, and fixes the
result in `AI_SLIDE_MATCHER_VERSION`. Review and update all three values plus
the reviewed public-file digests together when adopting a new matcher revision.
Public distribution must remain authorized by the matcher copyright owner. The
packages retain the matcher `LICENSE` and `THIRD_PARTY_NOTICES`.

All matcher gates run directly inside this public Obscura workflow. It does not
call a reusable matcher workflow, dispatch the private repository, wait for its
CI, or download artifacts from a private matcher run. The private repository is
used only as an immutable, read-only source checkout at the pinned commit.

1. Open **Actions → Release → Run workflow** and select the exact branch whose
   current commit should be released.
2. The workflow selects the version automatically. It reuses the highest
   stable `vMAJOR.MINOR.PATCH` tag already attached to the selected commit;
   otherwise it increments the patch component of the highest stable version
   found in repository tags or existing GitHub Releases. This prevents a
   deleted release tag from making an old version available again. A repository
   without a stable version starts at `v0.1.0`.
3. Select **build** to create downloadable workflow artifacts only, or
   **publish** to create or update a public GitHub Release after every build
   succeeds.

A repository-wide concurrency guard prevents two release requests from
selecting a version simultaneously. GitHub Actions retains only one pending
request in that concurrency group, so do not queue several manual releases at
once. Manual publication creates the selected missing stable tag at the chosen
commit, generates release notes for a new Release, and publishes a non-draft
release. Rebuilding a commit that already has a stable tag reuses that tag;
updating an existing Release preserves its notes, and publishing an existing
draft makes it public. To publish a major, minor, or prerelease version, push an
explicit SemVer tag such as `v1.0.0`, `v0.2.0`, or `v0.2.0-rc.1`; tag-triggered
runs preserve that version and mark prerelease versions automatically.

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

A separate matcher gate runs locked source and packaging tests, then native
release tests on five platform runners. Every native binary must pass the
match/compare and Tianai, GoCaptcha, AJ-Captcha, and slider-captcha-js adapter
smoke cases plus platform ABI checks. Obscura-owned policy validates each raw
smoke manifest against eleven exact cases and rebuilds a canonical public copy;
the raw private manifest remains runner-local. A read-only aggregation job
compares the five sanitized manifests, verifies deterministic archives
byte-for-byte against the tested binaries, removes the
implementation-documentation ZIP, and uploads
only platform binary archives, legal/runtime material, sample inputs, and a
small provenance record. The private checkout, source tree, tests, and
implementation documents are never release artifacts. Compiler, test, and
packaging output from private source commands is retained only in runner-local
temporary logs and is not printed or uploaded, preventing failure diagnostics
from exposing source excerpts. The final write-enabled job still only collects
the verified public artifacts, regenerates the combined `SHA256SUMS`, and
publishes them.

Only the final publish job receives `contents: write`; it does not check out or
execute repository code. The build jobs remain read-only. A tag created by the
repository `GITHUB_TOKEN` does not start another workflow, so a tag created by
manual binary publication does not automatically run the separate Docker
workflow. When a Docker image is required too, create and push the tag through
the normal Git flow instead of using the manual **publish** mode; that tag push
starts both the binary Release and Docker workflows.
