---
id: atlas.decision.0079.manifest-targets-outside-their-directory
type: decision
status: accepted
canonical: true
---
# ADR 0079 — A crate root is its manifest's target path, normalized, wherever it lies (G164)

## Context

FULL_OSS_REPLAY R8 put google/crubit, at its admitted legacy pin `34c96fb368e1`, in front of Atlas E12. Crubit is Rust/C++ interop: 890 Rust files, 507 `.cc` and 637 `.h` files, built primarily with Bazel. Its Cargo build is a parallel tree of manifests under `cargo/`, and each points its targets back into the source tree, for example `[lib] path = "../../../cc_bindings_from_rs/cmdline.rs"`.

Atlas E12 censused the whole workspace (2.5 GB peak, 22 s). Of 33,946 CALL records it resolved 154 INVOKES. The challenge was: what does `cc_bindings_from_rs`'s `main` reach to generate bindings? Atlas answered with nothing: 6 unresolved call sites in `main`, 1 in the closure passed to `and_then`, and no reason given.

The cause is in `crate_targets`. The manifest's directory and its target path were joined textually, so `cargo/cc_bindings_from_rs/cmdline/../../../cc_bindings_from_rs/cmdline.rs` never matched the inventory path `cc_bindings_from_rs/cmdline.rs`. Of crubit's 174 crate targets, 50 climb out of their manifest's directory this way, and all 50 exist once normalized. No crate root reached them, so their files were never evaluated. The census obligation said so ("no Cargo target's module tree reaches it"); the agent lenses did not.

Cargo resolves a target path relative to the manifest's directory, so `..` is legitimate.

## Decision

A manifest target path (`[lib] path`, `[[bin]] path`, `build`, and Cargo's defaults when they exist) is resolved against the manifest's directory with `.` and `..` segments collapsed. The result is the inventory path of the crate root. A target that climbs above the repository root is not a workspace source: it yields no crate, and a library that yields none binds no extern.

## Consequences

- **The same pin at E12 and E13:**
  - resolved INVOKES: 154 → 1,657 (all 154 kept);
  - SUPPLIES_DATA: 54 → 1,316;
  - unresolved call sites: 33,587 → 31,802;
  - RESOURCE records: 0 → 2 (a thread spawn and its join, checked against the source);
  - TYPE records: 13,201 → 13,813;
  - EFFECT records: 1,962 → 1,996;
  - PERSISTENCE records: 15 → 35.

  20 of 20 sampled new edges are correct against the source.
- **The challenge is answered.** `main` calls `Cmdline::new` (`cmdline.rs:211`), and its closure calls `run_with_cmdline_args` (`lib.rs:307`).
- **Test and mutants.** A synthetic fixture now carries the case: a climbing library and binary, a renamed path dependency bound through the normalized root, and an escaping target refused. 5 mutants were killed.
- **What remains UNKNOWN on crubit:**
  - the C++ side, which has no frontend: `extern "C"` declarations resolve, and their definitions in `.cc` files are UNKNOWN;
  - 917 of 947 FOREIGN_FUNCTION declarations, which sit in generated golden test files that no crate compiles;
  - member calls on rustc's `TyCtxt` API;
  - child processes, which are not in the resource table.
