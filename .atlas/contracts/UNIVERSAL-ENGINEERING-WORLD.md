---
id: atlas.contract.universal-engineering-world
type: contract
status: active
canonical: true
---
# Universal Engineering World Contract

## Purpose

Atlas is meant to be a universal engineering-world system. It ingests heterogeneous inputs:
- source languages;
- documents and media;
- UI designs;
- 3D, CAD and electronics artifacts;
- other engineering representations.

It preserves their original fidelity, converts their meaning into one evidence-backed world model, selects and verifies designs, and deterministically materializes target-specific worlds.

This contract fixes the architecture that goal requires. It also states **what exists today and what does not**. Universality is an architecture goal, not a current-state label. Measured support levels (below) are the only admissible statement of how far Atlas understands a subject.

## Architecture

```text
reality / intent / repositories / assets / designs
  → ingestion (per-language and per-artifact-class adapters)
  → universal engineering semantics (one typed record contract)
  → engineering world (composition)
  → *.atlas            one logical world, possibly physically sharded
  → candidate designs → comparison / verification → SelectedDesign → seal
  → ConstructionTaskGraph → target materialization
  → *.atlasx per selected design coordinate (one target each)
  → target compiler / backend → native artifact
  → observe / profile / recensus ↺
```

## Invariants

1. ATLAS IS UNIVERSAL AT THE LEVEL OF ENGINEERING MEANING, NOT AT THE LEVEL OF ONE MACHINE REPRESENTATION.
2. UNIVERSAL SEMANTICS ≠ UNIVERSAL ENCODING. A PNG stays a PNG when its bytes matter. Atlas wraps an artifact in identity, semantics, evidence and provenance; it does not re-encode every format.
3. SOURCE LANGUAGE IS AN INPUT REPRESENTATION, NOT THE ENGINEERING WORLD.
4. ORIGINAL ARTIFACT FIDELITY MUST NOT BE SILENTLY DESTROYED. A derived representation records DERIVED_FROM, the transformation, its parameters, lossless or lossy, and the quality constraint it satisfies.
5. ONE LOGICAL ENGINEERING WORLD MAY HAVE MANY PHYSICAL SHARDS. Large payloads may live in content-addressed storage outside the root. Completeness outranks co-location.
6. ONE SEALED DESIGN MAY HAVE MANY TARGET MATERIALIZATIONS, and TARGET SPECIALIZATION MUST NOT FORK CANONICAL PRODUCT IDENTITY.
7. EVERY MATERIALIZED ARTIFACT MUST HAVE TRANSFORMATION LINEAGE back to its sealed root, its SelectedDesign coordinate and its target.
8. UNSUPPORTED IS BETTER THAN FABRICATED SEMANTICS.
9. UNIVERSAL PRODUCT MEANING ≠ LOWEST COMMON DENOMINATOR UI. The universal behavior is kept; typed, explicit target specializations may be added.
10. AI PROVIDERS BUILD CANDIDATES; THEY DO NOT DEFINE TRUTH. AI IS NOT ATLAS; ATLAS IS NOT THE AI.
11. MULTILANGUAGE MEANS SHARED SEMANTIC CONTRACTS, NOT MULTIPLE PARSERS. Every language adapter emits the same typed records. There is no per-language world model.
12. FILE DISCOVERY IS NOT UNDERSTANDING, and SYNTAX PARSING IS NOT SEMANTIC UNDERSTANDING.

## Measured support levels

Every language and every artifact class of a revision is placed on one ladder, from that revision's own inventory, census and world model (`core::coverage::measure`; CLI `coverage levels`). A level is the highest rung whose evidence exists, and every rung below it must hold too.

| Level | Meaning | Evidence |
|---|---|---|
| L0 DISCOVERED | the inventory holds it | an artifact |
| L1 IDENTIFIED | a registered frontend names its language | the artifact's language |
| L2 SYNTAX | admitted for parsing | disposition PARSED |
| L3 TYPED_RECORDS | semantics begin | typed records whose provenance is the artifact |
| L4 OBLIGATIONS_EVALUATED | a dimension is decided | an obligation OBSERVED or DERIVED |
| L5 COMPOSED | in the engineering world | composed functions from the artifact |
| L6 AGENT_USABLE | the pilot can follow it | a composed function with a DERIVED relation |

- **Semantic support starts at L3.** A language at L2 is parsed, not understood.
- **An artifact class that no frontend identifies stays at L0.** Examples are an image, a video, a CAD or electronics file, or C with no frontend. Its class comes from the extension only.
- **A claim above the measured level is refused** (`validate_claims`), and so is a claim for a subject that was never measured.
- **Claims are checked by a test.** `.atlas/roadmap/SUPPORT-LEVELS.toml` holds the repository's claims and the measured report they rest on.

## Current state (G155, measured)

- **Rust: L6.** Thirteen dimensions (RESOURCE since G157, ADR 0072), a path resolver, and composition.
- **JavaScript: L6 on Atlas Studio's own three browser scripts.** This comes from the bounded G152 profile: functions, signatures, symbols, and CALL with same-file lexical resolution. Every other dimension is UNSUPPORTED.
- **TypeScript: not measurable on Atlas Studio**, which has no TypeScript artifact. Measured on the xyflow pin (replay R5, G158): **L6**, with 451 artifacts and 2,249 composed functions. FUNCTION_IDENTITY, FUNCTION_SIGNATURE and SYMBOL are OBSERVED. CALL is UNKNOWN: same-file resolution plus module linking across imports and workspace packages (ADR 0073). Every other dimension is UNSUPPORTED. Svelte components are L0.
- **CSS, HTML, JSON, Markdown, TOML: L2.** Syntax only.
- **C, C++, Python, Go, Swift, Zig: L0.** No frontend. Since G154, calls into C through Rust `extern` declarations resolve to FOREIGN_FUNCTION records.
- **Image, video, audio, document, UI design, CAD/3D, electronics: L0** (DEBT-ARTIFACT_SEMANTICS).
- **Target profiles: absent** (DEBT-TARGET_PROFILE). `SelectedDesign.target_kind` is a free string.
- **AtlasX: contract only** (DEBT-ATLASX; construction nodes M8 onward are missing).
- **Construction IR: v0 for type declarations and signatures, pre-AtlasX** (ADR 0069). It has no bodies and no barriers.
- **Native backend:** a never-guessing Rust source backend for SELF_RECONSTRUCTION shadows. No delegated backend produces an admitted artifact.
- **Cross-target reproduction: none.**

## AtlasX and targets

`*.atlasx/` materializes one selected design coordinate (scope, target kind, variant) from one sealed root (`ATLASX-FORMAT.md`, `SELECTED-DESIGN.md`).

Many targets therefore means many selected coordinates over the same sealed root. A family such as `product.atlasx/<target>/` is a projection of those roots. Their shared parent root and the shared product identity above the coordinate are what make them one product.

A `TargetProfile` must describe:
- OS family, architecture, ABI and runtime;
- capabilities: GPU, camera, input, filesystem, network, permissions, codecs;
- packaging, signing and deployment constraints.

A physical device is evaluated against a profile family. A design requiring a capability its target lacks is incompatible. It is never silently degraded unless a fallback is declared. None of this is implemented; it is DEBT-TARGET_PROFILE, attack NA-TARGET-PROFILE.

## Artifact model

Every admitted input is conceptually a typed artifact with the following fields:
- identity;
- kind;
- content digest;
- original representation;
- semantic representation;
- dependencies;
- transformations;
- provenance;
- evidence;
- uncertainty;
- target constraints.

Today the inventory carries identity, path, kind (file, symlink, policy boundary, special), disposition, language and digest. Semantic representations exist only for source languages at L3 and above. Non-code classes are DEBT-ARTIFACT_SEMANTICS, and the first attack, NA-ARTIFACT-SEMANTICS-IMAGE, lifts images from L0 to L3.

## Weight artifacts (G163, ADR 0078)

Neural-network weights are an artifact class under DEBT-ARTIFACT_SEMANTICS. They extend the census, construction and provenance machinery above. There is no separate subsystem and there are no pairwise format converters: every format is censused into one physical record, and every output is constructed from that record.

**Two layers, never merged.**
- *Physical* (`atlas.weight-census.v1`, EXPERIMENTAL): the artifact digest and length, the payload offset and length, and free-form metadata. Per tensor: its name, dtype, shape, payload byte range and BLAKE3 digest. Ranges tile the payload exactly.
- *Semantic*: which role a tensor plays (embedding, attention projection, norm scale, quantization scale or zero point), and which architecture it realizes. It is UNKNOWN in every census today. A tensor name is evidence to be checked, never a role.

**Payloads stay outside the container.** `.atlas` v1 is THIN: a weight census references its payload by artifact digest, byte range and per-tensor digest, and never carries the bytes. `.atlasx` projects a SelectedDesign and is not a weight store. Activation of self-hosted weights is a separate admission event (`ORGANISM-MODEL-ADMISSION.md`).

**Mechanical construction.** An output is written only from the typed census record and from source byte ranges verified against their digests. The header is rebuilt from the record, never copied, and the AI writes no bytes. A construction claims content preservation only after the output's own census matches the source's.

**Preservation classes.**
- `LOSSLESS`: content equal, bytes may differ.
- `REVERSIBLE_WITH_RETAINED`: exact reconstruction is claimable only while the retained residual is present.
- `LOSSY`: never exact.

Quantization, dtype casts and pruning are LOSSY unless they retain a residual.

**Security.** Parsing is data-only:
- bounded header lengths, with duplicate keys, unknown fields and unknown dtypes refused;
- the structure checked before any payload byte is read;
- streaming in fixed chunks.

Pickle-based checkpoints are never unpickled: no format other than SafeTensors is read today, and a PyTorch zip archive may later (W5) be censused only as a zip of data records, never by executing its pickle.

**Staged roadmap** (NA-ARTIFACT-SEMANTICS-WEIGHTS and successors):

| Stage | Capability | Maturity |
|---|---|---|
| W1 | SafeTensors physical census, lossless mechanical re-encoding, CLI `weights census` / `weights construct` | EXPERIMENTAL, verified by tests and the reference implementation as oracle |
| W2 | weight census records in the self census (typed record family, inventory class, support ladder level) | PLANNED (NA-WEIGHT-CENSUS-RECORDS) |
| W3 | semantic role mapping from structural evidence (shape families, tying, graph metadata), with names as hints only | PLANNED (NA-WEIGHT-ROLES) |
| W4 | transforms with typed preservation: dtype casts, quantization with a retained residual, sharding and merging | PLANNED (NA-WEIGHT-TRANSFORMS) |
| W5 | further formats censused into the same record: GGUF, ONNX initializers, PyTorch zip archives (no pickle), MLX | PLANNED (NA-WEIGHT-FORMATS), each after its donor replay |

**Donor classification.**
- ggml-org/llama.cpp (GGUF, quantization kernels)
- huggingface/safetensors (format)
- huggingface/transformers (architecture configs, name conventions)
- pytorch/pytorch (checkpoint archives)
- onnx/onnx (graph initializers)
- ml-explore/mlx (array formats)

These families are explicitly authorized FULL_OSS_REPLAY donors, all NEVER_REPLAYED. Each is replayed one at a time at an exact pin, with its license verified at that pin. Their knowledge is classified per area (format, quantization, architecture, runtime) as mechanism or reference. Nothing is absorbed or extinct until its replay decides so.

## Product model and capability-first design (conceptual)

Above language and platform, an application is modelled as:
- screens;
- user flows;
- components;
- commands;
- events;
- data models;
- permissions;
- assets;
- navigation;
- accessibility;
- constraints;
- the capabilities it requires.

A capability can be bound to one or more concrete realizations: a key-value store, a camera, notifications, GPU rendering, secure storage. A SelectedDesign binds a capability to a concrete realization per target. None of this is implemented beyond ADL-declared capabilities and SelectedDesign bindings; it converges through DEBT-DESIGN_GENERATION, DEBT-TARGET_PROFILE and DEBT-ARTIFACT_SEMANTICS.

## Anti-cheat

The following claims are false, and the repository must not make them:

| Claim | False while |
|---|---|
| "supports every language" | only syntax is parsed (L2) |
| "supports media" | only a filename and a hash are known (L0) |
| "supports Android or iOS" | no target profile or lowering exists |
| ".atlasx exists" | only a directory mockup exists |
| "universal" | one backend or language is hardcoded into the core |
| "the same application" across targets | the builds share no semantic identity |
| "lossless transformation" | there is no provenance or evidence |
| "weight support" or "understands the model" | only the physical layer is censused and roles are UNKNOWN |
| "lossless quantization" | no retained residual reconstructs the original exactly |
| "target compatible" | there is no capability check against a target profile |

Enforcement:
- `validate_claims` and the support-level ledger test refuse the first two.
- The rest stay debts until their mechanisms exist.

## Roadmap shape

The architecture proves itself narrowly first:
1. design candidates;
2. selection;
3. seal (M8, M9);
4. minimum real AtlasX (M10–M13);
5. construction IR;
6. one real target backend (M15, M16);
7. first produced artifact (M17, M18);
8. recensus;
9. a second target with a TargetProfile;
10. a cross-target identity proof;
11. heterogeneous asset and language expansion.

FULL_OSS_REPLAY keeps running beside this with heterogeneous donors, and every capability epoch re-opens the verdicts it could change.
