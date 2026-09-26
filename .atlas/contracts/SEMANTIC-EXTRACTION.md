---
id: atlas.contract.semantic-extraction
type: contract
status: active
canonical: true
---
# Semantic Extraction Contract

## Purpose

**SourceFrontend** owns structural source recognition. A semantic extractor owns evidence-producing analysis behind that frontend. Neither owns canonical truth.

Registered frontends (`adapter/src/source/frontend.rs`) recognize rust, typescript, javascript, markdown, toml, json, yaml, html and css by extension. A tenth, `rust-include-fragment` (G61), is never recognized by path. A file gets that language only when a `.rs` file in the same directory calls `include!("<its name>")`, observed at token level. `include_str!` and `include_bytes!` targets are data, not Rust tokens.

Symbol and type identities carry the source artifact that spells them (G67, ADR 0029). A lexical scope names no module, so without the path, equal spellings in different files were one identity. A resolved `canonical` type ignores the path.

Recognition is not analysis. A recognized language with no registered SemanticExtractor gets an explicit UNSUPPORTED batch for every dimension. The batch is attributed to the dispatch identity `atlas.extraction.unsupported-language` (G62). That identity is not an extractor and evaluates nothing. An unrecognized file stays UNKNOWN; it is never guessed.

R4 extraction converts a pinned admitted artifact into typed raw observations and explicit unresolved obligations. It does not normalize identities globally, reconcile conflicts, invent facts, or write the engineering graph directly.

## Canonical path

~~~text
Inventory
→ SourceFrontend
→ SemanticExtractor
→ Raw typed observations
→ Census
→ Normalize
→ Reconcile
→ Engineering Graph / ATLAS projection
~~~

There is one normalized semantic path. Direct extractor → graph, parser → graph or compiler-metadata → graph shortcuts are forbidden.

## Extractor identity

Every extractor MUST expose a stable identity and implementation version. Results are attributable to both.

Conceptual obligation:

~~~text
SemanticExtractor
├─ id
├─ version
├─ supported_languages
├─ semantic_dimensions
└─ extract(ExtractionInput) → ExtractionBatch
~~~

The physical Rust trait may differ, but these obligations may not disappear.

## ExtractionInput

An input MUST identify repository, exact revision, artifact identity/path, content fingerprint when available, source frontend identity, language/profile, scope policy, requested semantic dimensions and relevant build/config profile.

Extractors MUST NOT read undeclared mutable global state as semantic input.

## ExtractionBatch

~~~text
ExtractionBatch
├─ extractor_id/version
├─ artifact/revision identity
├─ typed observations[]
├─ evidence[]
├─ obligation results[]
├─ dynamic/unresolved records[]
├─ diagnostics[]
└─ input fingerprint
~~~

Every requested dimension receives an obligation result. Silent omission is forbidden.

## Semantic dimensions

Minimum R4 dimensions:

~~~text
SYMBOL
TYPE
FUNCTION_IDENTITY
FUNCTION_SIGNATURE
CALL
CONTROL_FLOW
DATA_FLOW
STATE
EFFECT
OWNERSHIP
CONCURRENCY
PERSISTENCE
~~~

Build/dependency metadata may come from dedicated resolvers/extractors but enters the same census path. Dependency extraction MUST satisfy `DEPENDENCY-CENSUS.md`: root-manifest parsing alone is insufficient; resolution is contextual and transitively closed.

## Dependency extraction boundary

A package/build ecosystem adapter may discover dependency declarations and resolution evidence, but it does not own dependency truth.

Conceptually:

~~~text
DependencyResolver
├─ id/version
├─ supported ecosystems/build systems
├─ resolve(root, resolution_context)
└─ → typed dependency nodes + edges + diagnostics + evidence
~~~

Resolved dependency records enter Census before normalization/reconciliation. Independent sources such as manifests, lockfiles, package-manager metadata, compiler metadata, binary linkage and runtime traces may disagree; such disagreements remain explicit reconciliation obligations.

Source-backed dependency nodes are recursively admitted to inventory/census until dependency fixed point. Non-source nodes terminate only through explicit typed boundary disposition.

## Obligation result

For each requested dimension and applicable scope, an extractor emits one of:

- evidence-backed OBSERVED facts;
- verified absence with closure evidence;
- UNKNOWN;
- UNSUPPORTED;
- policy-backed IGNORED;
- observations that later reconcile into CONFLICT.

UNKNOWN means evidence is insufficient. UNSUPPORTED means the current extractor/runtime cannot perform the analysis. They are not interchangeable.

A dimension MAY emit evidence-backed observations while its overall obligation remains UNKNOWN when the extractor covers only part of the dimension's declared semantic surface. UNKNOWN with non-empty observation identities means "useful partial evidence exists; closure is not proven." Verified absence is permitted only when the full declared obligation scope for that extractor/profile was exhaustively checked. A partial STATE/EFFECT extractor MUST NOT turn "no fact found in the subset I understand" into a negative semantic fact about unmodeled state/effect forms.

## Determinism

For identical artifact content, repository revision, extractor version, language/build profile and scope policy, output MUST be semantically equivalent independent of traversal order, thread scheduling or filesystem enumeration order.

Generated record IDs must not depend on nondeterministic collection ordering.

## Evidence rules

Observed facts identify the admitted source/revision and relevant span/metadata record when available.

Parser output, compiler metadata and runtime traces are evidence sources, not truth owners.

AI/model analysis MUST NOT emit OBSERVED source facts. Model-assisted analysis enters as INFERRED or HYPOTHESIS until corroborated by an allowed observation path.

## Dynamic behavior

Reflection, dynamic dispatch, macros/proc-macros, generated code, FFI, SQL/shell strings, plugin loading, feature flags and environment-driven behavior require explicit records.

Allowed outcomes include resolved target sets, partial sets, dynamic placeholders and unknowns. “Could not resolve” never means “does not exist”.

## Multi-engine extraction

Independent extractors MAY analyze the same dimension. Their identities/evidence remain separate. Disagreement creates a reconciliation obligation; one extractor may not overwrite another.

**Implementation note (G75, ADR 0031)**: CALL has two engines. `atlas.rust.source-semantic.v1` observes every call site (callee `UNRESOLVED`). `atlas.resolution.rust-paths` resolves path calls natively, crate-wide: module tree, items, `use` imports to a fixed point, block scopes, the extern prelude of workspace crates, and inherent/trait-impl associated functions. It observes the same claim (`record_id`) with `STATIC_RESOLVED` and the callee's FunctionIdentity record. It is asked for CALL only, so accounting closure holds each engine to the dimensions it was asked for. An UNRESOLVED observation makes no callee claim, so it is not a disagreement with a resolution; two different resolutions are. A resolution that matches no syntactic claim is a diagnosed engine disagreement, never a record. Unsound cases stay unresolved with a reason: locals, generic parameters, open scopes (item macros, external globs), ambiguity, trait dispatch, constructors. G162 (ADR 0077): every open scope records its cause, and an artifact with calls withheld there carries an `INCOMPLETE_ANALYSIS` diagnostic prefixed `open scope: ` naming each cause; a period-2 oscillation of the import fixed point (a placeholder travelling around a re-export cycle) is merged conservatively instead of opening every module. G164 (ADR 0079): a crate root is its manifest target path (`[lib] path`, `[[bin]] path`, `build`, or Cargo's defaults) resolved against the manifest directory with `.` and `..` collapsed, so a manifest kept in a parallel tree still roots its sources; a target above the repository root is no crate. A file no crate root reaches is not evaluated, and its obligations say so. The pinned rust-analyzer SCIP output is the differential verification oracle, never a census input.

**Implementation note (G83, ADR 0034)**: the engine also evaluates TYPE. It claims a type spelling as denoting a canonical type (`TypeIdentity.canonical`, file path excluded, so the claim is shared across files) when three things hold:
- the syntactic extractor recorded that spelling in the artifact;
- every occurrence of the spelling there resolves;
- they all resolve to that one type.

Workspace types are canonical as `<package> <module path>/<Name>#`, and standard-library types by their std path, composed structurally. A generic parameter, a generic `Self`, an opaque alias or a glob name in an open module never yields a claim.

**Implementation note (G79, ADR 0033)**: the engine also resolves `self.m()` inside impl methods. The receiver has the impl's self type, and the method probe's first step picks the unique inherent method whose receiver form equals the caller's, provided its impl has the same generics and self-type arguments. Any other method call waits for type inference.

**Implementation note (G77, ADR 0032)**: the same engine also evaluates EFFECT. A path call it resolves to a standard-library path named by the declared std-path effect table (`atlas_core::std_path_effects`: `std::fs` entry points) is a DERIVED FILESYSTEM_READ/WRITE effect site of the caller, anchored at the call. A path the table does not name declares nothing.

## Failure semantics

Extractor crashes, parser errors, resource limits and unsupported syntax become diagnostics plus UNKNOWN or UNSUPPORTED according to cause. A failure must not remove the artifact from census accounting.

**Implementation note (R4.3.5/R4.3.6, `adapter::semantic::rust`)**: a resource-limit failure mode is now real, not only declared vocabulary. `syn` is a recursive-descent parser with no built-in recursion-depth protection; nothing previously bounded the structural recursion depth an admitted artifact's source could drive, only its byte size (`MAX_SEMANTIC_BYTES`, a separate, size-only gate). A small file that drives deep parser recursion reliably overflowed the stack and aborted the whole extraction process -- for every artifact in the run, not just the pathological one -- rather than producing a diagnostic. `RustSemanticExtractor::extract` now pre-scans raw source text for structural recursion risk (`max_structural_recursion_risk`) before ever invoking `syn`, and refuses to parse (every supported dimension `UNKNOWN`, `DiagnosticCode::ResourceLimit`) above `MAX_STRUCTURAL_RECURSION_RISK = 64`.

This guard covers three independently-confirmed, structurally distinct crash vectors with one combined metric: explicit bracket nesting (`(((...)))` -- 300 levels reliably overflowed a reduced 2MB test-thread stack, 100 did not), a bracket-free chained binary-operator expression (`1+1+1+...` -- 2,000 terms reliably overflowed the same stack, 1,000 did not; bracket-nesting depth for such an expression is just 1), and an `if ... else if ... else if ... else { .. }` chain (3,000 arms reliably overflowed the same stack; each arm's own braces are siblings, not nested, so bracket-nesting depth stays at 2 regardless of chain length, and there is no operator-character run either). An initial fix (R4.3.5) caught only the first vector; continued adversarial testing (per the standing loop's own falsification discipline) found the second (R4.3.6) and then the third (R4.3.7), neither of which the earlier guards caught. `stacker`-based stack growth was tried as an alternative and found ineffective: it can only grow the stack at the moment it is invoked, and `syn`'s own internal recursive-descent calls never invoke it, so wrapping only the outer `syn::parse_file` call makes no difference (confirmed empirically: the same crash still occurred with a 256MiB `stacker::maybe_grow` wrapper). 64 sits far below all three observed crash floors and far above any real nesting/chain/else-arm length this repository's own source corpus has ever reached (max bracket depth 13).

**This guard is explicitly not claimed complete.** Three real vectors found in succession by continued falsification is itself evidence that a from-scratch, syntax-unaware text scan cannot exhaustively enumerate every construct that can drive `syn`'s recursion -- a fourth, fifth, ... construct (e.g. deeply chained `match` guards, deeply nested `loop`/`while let` chains, some other keyword-driven recursive AST shape) may exist and would not necessarily be caught. A fully complete fix would require either patching `syn` itself to grow its own stack during recursion (this bootstrap does not vendor or fork `syn`) or replacing whole-file parsing with a from-scratch, formally depth-bounded parser (a large undertaking, not attempted this wave). This is recorded as a known, open, honestly-acknowledged residual risk -- `.atlas/evidence/verification/r4.3.7-*.json` -- rather than a silently narrowed scenario search used to claim false convergence.

**Follow-up (`.atlas/evidence/verification/dos-guard-false-positive-elimination.json`): the guard's own false-positive rate was never verified against this repository's real, full source corpus, and it turned out to be a real, live census-blindness gap.** Directly re-censusing this repository's own real source (`atlas-cli code analyze`) found 9 of Atlas's own genuinely non-adversarial files tripping `ResourceLimit` and becoming fully invisible to semantic extraction -- not adversarial input, real production/test source this codebase has always contained. Two independent root causes, both in the original scan's `chain_run` counter: (1) `,` was counted toward the chain, but a comma-separated list (function-call arguments, struct-literal fields, tuple/generic parameters) is parsed *iteratively* by `syn` (a loop collecting a `Punctuated<T, Comma>`), never recursively per sibling, so a long ordinary argument list or struct literal was indistinguishable from a real recursive chain; (2) the scan had zero comment/string-literal exclusion, so this codebase's own common documentation style (`// --- section name ----------------------------` dash-divider comments) and an embedded raw-string test fixture were themselves counted as dangerous operator runs. Fixed: `,` now resets `chain_run` (like a bracket boundary) instead of extending it; `//` line comments and `"..."`/`r#"..."#` string literal content are now skipped entirely before scanning. Neither change weakens detection of any of the three confirmed vectors above, all of which occur in genuine code structure, never inside a comment, string, or comma-separated list -- removing non-adversarial content from consideration can only ever lower a computed risk, never hide a real one. Verified: all 9 previously-blind files now parse successfully with zero `ResourceLimit` diagnostics remaining anywhere in this repository's real self-census.

## Security boundary

Source is untrusted input. Extraction is analysis, not execution.

Executing build scripts, tests, proc-macros, binaries or project code requires a separately authorized/sandboxed capability.

## R4 acceptance matrix

| Requirement | Current bootstrap | R4 completion condition |
| --- | --- | --- |
| Semantic ontology | Contract locked | Runtime records map losslessly to typed FactKind families |
| Epistemic taxonomy | Six-state bootstrap | Canonical nine-state enum used end-to-end |
| Structural frontend | Materialized | Remains adapter recognition boundary; no graph authority |
| Semantic extractor interface | Missing | Native versioned extractor registry/output contract exists |
| Function identity/signature | Missing | Every discovered function has stable identity/signature or explicit unresolved status |
| Symbol/type | UNSUPPORTED | Evidence-backed facts or explicit scoped unresolved results |
| Call graph | UNSUPPORTED | Static/dynamic/unresolved calls represented without omission |
| CFG/dataflow | UNSUPPORTED | Applicable functions have typed facts or explicit obligation status |
| State/effect | UNSUPPORTED | Reads/writes/transitions/effects represented with evidence |
| Ownership/concurrency/persistence | Philosophy only | Applicable profiles emit typed facts or explicit scoped status |
| Revision/content evidence | Partial | Facts tied to pinned revision and input fingerprint |
| Normalization | Predicate bootstrap | Identity/equivalence/exact-dedup rules implemented |
| Conflict handling | Missing | Conflicting raw facts survive into reconciliation input |
| Graph path | Normalized facts feed graph | No parser/extractor bypass creates canonical semantics |
| CensusCertificate | Contract/schema only | Runtime issuance remains R6; R4 supplies required inputs |

### R4 Definition of Done

R4 closes only when:

1. all mandatory R4 dimensions for the declared reference language/profile are evidence-producing or explicitly accounted;
2. every discovered function has a stable identity record;
3. no mandatory dimension is silently absent;
4. normalization is deterministic and provenance-preserving;
5. exact semantic duplicates follow NORMALIZATION.md;
6. conflict candidates survive into reconciliation input;
7. graph construction consumes only the normalized path;
8. tests prove deterministic output and accounting closure;
9. SemanticFact remains a compatibility envelope, not the only semantic type system.

Any project-wide claim that R4 is complete MUST name the language/profile/reference corpus against which these gates were proven.

## Second language (G152, ADR 0068)

`atlas.typescript.source-semantic.v1` extracts TypeScript and JavaScript under the same `ExtractionBatch` and obligation contract. tree-sitter only parses. A parse is never a semantic support claim.

- **Profile:**
  - FUNCTION_IDENTITY, FUNCTION_SIGNATURE and SYMBOL are exhaustive on an error-free parse.
  - CALL is always UNKNOWN with its observations. Same-file lexical resolution is DERIVED.
  - Every other dimension is UNSUPPORTED.
- **Support levels on the replay target (GitNexus at 06ce60beb674):**
  - At E1, TypeScript was L1 (identified, UNSUPPORTED in every dimension).
  - At E2:
    - FUNCTION_IDENTITY, FUNCTION_SIGNATURE and SYMBOL are L3 with obligations evaluated (L4);
    - CALL is L3 with a bounded, same-file profile;
    - TYPE, DATA_FLOW and the rest stay UNSUPPORTED.
