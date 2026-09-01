# Optional online Tencent CAPTCHA smoke

Obscura has a manual, non-gating smoke test for the authorized target
`https://wiki.smzdm.com/p/z606zqm/`. It exercises the complete path from a
top-level navigation through a Tencent iframe to a `capture-ready` response
archive. It is deliberately absent from pull-request, branch, scheduled, and
release CI because the remote endpoint, challenge selection, and runner IP are
not deterministic.

Use this only for a system and CAPTCHA session that you own or are authorized
to test. The check reads image resources; it does not drag the slider or submit
a verification result.

## Run the manual action

Open **Actions > Optional online Tencent CAPTCHA smoke > Run workflow**. The
workflow must first exist on the repository's default branch before GitHub
shows its manual-run button. Select the Obscura revision to test.

`matcher_ref` is optional. Leave it blank to validate only the browser capture.
Set it to a lowercase full 40-character commit from
`vvhh2002/ai_slide_matcher` to build that revision, run its `gray` matcher, and
require the returned `[x,y]` center to lie inside the archived background
image. Tags and moving branch names are rejected. `wait_seconds` controls the fixed
observation window after the `capture-ready` boundary and defaults to eight
seconds.

Because the matcher repository is private, matcher-enabled runs require the
same protected `ai-slide-matcher-release` environment and its
`AI_SLIDE_MATCHER_READ_TOKEN`, scoped to **Contents: Read** on that repository.
The environment should allow only reviewed release refs. Capture-only runs do
not read the secret, although the job still passes the environment protection
gate. The source checkout remains on the ephemeral runner; only the existing
sanitized smoke report is uploaded.

The action has three outcomes:

- `ONLINE_SMOKE_PASS`: a live Tencent iframe was serialized, its frame-owned
  background and foreground sprite responses passed manifest length/hash
  checks, and the puzzle piece was reconstructed from the serialized CSS
  geometry. If a matcher was requested, its coordinate was in image bounds.
- `ONLINE_SMOKE_SKIP`: the target did not materialize a Tencent slider. This is
  expected remote variation and exits successfully.
- `ONLINE_SMOKE_FAIL`: Tencent slider evidence was present, but the iframe,
  image response, archive completeness, sprite geometry, or optional matcher
  check was wrong.

Only a sanitized JSON summary is uploaded. The disposable runner directory
contains the complete archive, including signed image URLs and response bodies,
but the workflow does not upload it. The live harness also caps the archive at
512 responses and 64 MiB.

The optional online job runs only on an Ubuntu x86_64 hosted runner. It does
not replace the Windows executable build and offline smoke coverage in the
release workflow.

## Run locally

Build the render/stealth binary, then invoke the same script:

```bash
CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 \
  cargo build --locked --release -p obscura-cli --bin obscura \
    --features render,stealth

python3 scripts/ci/tencent_captcha_online_smoke.py \
  --obscura target/release/obscura \
  --stealth \
  --work-dir /tmp/obscura-tcaptcha-smoke \
  --report /tmp/obscura-tcaptcha-report.json \
  --timeout 60 \
  --wait 8
```

To include a locally built matcher, add:

```text
--matcher /absolute/path/to/ai_slide_matcher
```

The matcher must implement the `ai_slide_matcher match --piece-file ...
--background-file ... --algorithm gray` command and emit exactly one JSON
coordinate array on success.

An existing Obscura archive can be inspected without another network request:

```bash
python3 scripts/ci/tencent_captcha_online_smoke.py \
  --archive /absolute/path/to/archive \
  --derived-dir /tmp/tcaptcha-derived \
  --report /tmp/tcaptcha-report.json
```

The archive and derived-output directories must be fresh because neither the
browser archive writer nor the smoke script overwrites prior evidence.

## Offline script check

The parser, manifest ownership checks, PNG sprite transform, pass path, skip
path, and missing-response failure are covered by a deterministic self-check
that uses only the Python standard library:

```bash
python3 scripts/ci/tencent_captcha_online_smoke.py --self-test
```

This command performs no network access and is run before the manual action's
release build.
