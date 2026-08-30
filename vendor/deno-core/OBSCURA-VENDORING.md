# deno_core vendoring record

- Package: `deno_core 0.350.0`
- Registry source: crates.io package cached by Cargo
- Source archive SHA-256: `e273b731fce500130790e777cb2631dc451db412975304d23816c1e444a10c5b`
- Upstream repository: <https://github.com/denoland/deno_core>
- License: MIT; see `LICENSE`

Obscura carries a narrow secondary-realm patch. It restores a managed snapshot
realm handle with a realm-local `ModuleMap`, initializes the embedder slots
required by dynamic import and import-meta callbacks, keeps registered realm
state owned until explicit retirement or isolate cleanup, and includes live
managed realms in `JsRuntime::poll_event_loop`. Explicit retirement removes a
detached realm from the runtime registry before destroying its module map and
context slots, so iframe churn does not retain or poll every old context. No V8
or deno_core version upgrade is part of the patch.

## Local patch surface

- `runtime/jsrealm.rs` owns the public `ManagedJsRealm` handle, its idempotent
  retirement API, its realm-local module/event-loop state, and the explicit
  unregistered side-root loading path used by HTML inline modules.
- `runtime/jsruntime.rs` creates managed realms from a snapshot, initializes
  module embedder data, strongly owns registered managed realms through a
  shared retirement-aware registry, and polls only its live entries.
- `modules/map.rs`, `modules/module_map_data.rs`, and
  `modules/recursive_load.rs` retain an inline root by id/handle without
  registering its shared document URL in the name map. The canonical name is
  still used as V8's ScriptOrigin and dependency referrer, while graph loading
  starts from the explicit ModuleId after the import-map snapshot is frozen.
  `modules/map.rs` also exposes the instantiated static graph's module ids and
  canonical specifiers to the browser scheduler, and turns a repeated
  evaluation of an already completed module into an idempotent result instead
  of an assertion across the V8 boundary. An errored module still returns its
  original V8 exception, and an evaluation already in progress remains an
  explicit error.
- `runtime/mod.rs` and `lib.rs` expose the managed-realm API to Obscura.

The remainder is the normalized `deno_core 0.350.0` crates.io source package.
Keep the package version pinned and retain this source record in the repository.
Distributions containing a copy or substantial portion of deno_core must retain
the upstream copyright and MIT permission notice from `LICENSE`. Record any
future local change in the patch-surface list.
