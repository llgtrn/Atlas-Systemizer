//! Atlas runtime orchestration.

pub mod agent;
pub mod atlas;
pub mod census;
pub mod certificate;
pub mod design;
pub mod donor_storage;
pub mod integrity;
pub mod inventory;
pub mod normalize;
pub mod physical;
pub mod product;
pub mod recensus;
pub mod sandbox;
pub mod seal;
pub mod self_reconstruction;
pub mod verification;
pub mod visual;
pub mod weights;

use atlas_core::{
    AdlCompileReport, AdlProgram, CLI_API, CodingAdmission, ConstraintResult, ConstraintVerdict,
    Contract, DependencyClosureReport, DependencyClosureState, DependencyEcosystem, DocsReport,
    EngineeringGraph, Evidence, InventoryReport, RepoAudit, RepoManifest, RepositoryId,
    RevisionRef, SystemizeReport, WorkPrepareReport, WorkRequest, add_constraint_derivations,
    add_dependency_closure, build_system_graph, compile_adl, diff_inventories, parse_adl_source,
    summarize_system_graph_with_dependencies,
};
use std::{io, path::Path};

/// The real, evidenced Cargo dependency closure for `root` (`census_cargo_workspace`), or a
/// `NotApplicable` report when no `Cargo.lock` exists at all -- never a fabricated empty-but-
/// `Closed` report (`.atlas/contracts/DEPENDENCY-CENSUS.md#implementation-status`). Shared by
/// every entry point that needs the closure (`systemize`, `graph`, `code_analyze`) so they can
/// never disagree about which state a given root resolves to.
fn resolve_dependency_closure(root: &Path) -> io::Result<DependencyClosureReport> {
    Ok(
        adapter::census_cargo_workspace(root)?.unwrap_or_else(|| DependencyClosureReport {
            schema: "atlas.dependency-closure-report.v4".into(),
            ecosystem: DependencyEcosystem::Cargo,
            root: root.to_string_lossy().into_owned(),
            state: DependencyClosureState::NotApplicable,
            edges_total: 0,
            instances_total: 0,
            edges: Vec::new(),
            dangling_references: Vec::new(),
            unsupported_constructs: Vec::new(),
            dynamic_obligations: Vec::new(),
            reachability: None,
        }),
    )
}

/// The `RepositoryId` extraction/census pin for `root`: the declared manifest repo name when one
/// exists, else the canonicalized root path. Shared by every entry point that runs extraction so
/// they all pin identity the same way.
fn resolve_repository_id(repository: &RepoAudit, root: &Path) -> RepositoryId {
    RepositoryId::new(
        repository
            .manifest
            .as_ref()
            .map(|manifest| manifest.repo.clone())
            .unwrap_or_else(|| root.to_string_lossy().into_owned()),
    )
}

/// `WorkRequest.allowed_paths`: every root a manifest declares across `source_roots`,
/// `backend_roots`, `frontend_roots` and `test_roots` -- all four, per
/// `.atlas/contracts/EXTERNAL-PROVIDER-TRUST.md#capability-minimum`'s own documented rule that
/// these are "joined against the repository root before walking the filesystem" -- filtered
/// through the same `declared_root_is_contained` predicate `adapter::inventory_declared_source`
/// itself already enforces, sorted, and deduplicated. `backend_roots` was validated for
/// path-escape by `core::constraint::validate_manifest` from the day that field existed, but was
/// silently omitted from this list (and from `inventory_declared_source`'s own walk) until this
/// fix: a manifest declaring a `backend_roots` entry not already covered by one of the other three
/// fields produced zero artifacts for it and granted an external provider zero capability to touch
/// it, even though it is legitimate, admitted repository source.
///
/// A manifest-declared root that escapes the repository boundary is already caught by
/// `validate_manifest`/`repository.ready` (a `REPO_GATE_NOT_READY` blocker, which makes
/// `prepare_work`'s own `allowed` field `false`) and is never walked by `inventory_declared_source`
/// regardless. Filtered again here as defense in depth: `allowed_paths` is the literal
/// capability-scoping data an external provider reads to know what it may touch, so it must never
/// contain an escaping entry even if some future caller inspected this list without first checking
/// `allowed`/`coding_admission`.
///
/// Extracted as a pure function (matching `resolve_dependency_closure`/
/// `build_coverage_from_dependency_closure`'s own precedent) so this exact list-construction logic
/// is directly, cheaply unit-testable without running the full `systemize` pipeline against a real
/// on-disk repository -- the gap this function itself closes was previously invisible precisely
/// because no test exercised it in isolation.
fn work_allowed_paths(manifest: Option<&RepoManifest>) -> Vec<String> {
    let Some(manifest) = manifest else {
        return Vec::new();
    };
    let mut paths = manifest.source_roots.clone();
    paths.extend(manifest.backend_roots.clone());
    paths.extend(manifest.frontend_roots.clone());
    paths.extend(manifest.test_roots.clone());
    paths.retain(|path| atlas_core::declared_root_is_contained(path));
    paths.sort();
    paths.dedup();
    paths
}

/// `BUILD` coverage promotion and coding-admission blocking, derived purely from a
/// `DependencyClosureReport`'s `state` (`.atlas/contracts/DEPENDENCY-CENSUS.md#implementation-status`).
/// Returns `(coverage update, whether this state blocks coding admission)`. Extracted as a pure
/// function so the exact defect it replaces -- a fabricated `NotApplicable` report whose
/// `dangling_references.is_empty()` made `is_closed()` silently read `true`, so a repository with
/// no Cargo workspace at all never raised `DEPENDENCY_CLOSURE_NOT_CLOSED` and looked identical to
/// a genuinely verified empty closure -- is directly, cheaply falsifiable without running the full
/// `systemize` pipeline.
fn build_coverage_from_dependency_closure(
    state: atlas_core::DependencyClosureState,
) -> (Option<atlas_core::EpistemicStatus>, bool) {
    use atlas_core::{DependencyClosureState as State, EpistemicStatus as Status};
    match state {
        State::Closed => (Some(Status::Observed), false),
        State::Partial | State::Blocked => (Some(Status::Unknown), true),
        State::NotApplicable => (None, false),
    }
}

/// Whether `coding_admission` must block on ADL constraint/invariant/materialization-delta
/// evaluation. Extracted as a pure function so the exact defect it replaces -- this gate
/// previously inspected only `adl.diagnostics` (parse/link diagnostics), never
/// `adl.constraint_results` (the sibling field `evaluate_constraints` and the declared/observed
/// materialization deltas actually report failures through), so a declared constraint, invariant,
/// or materialization could fail while `coding_admission.allowed` stayed `true` -- is directly,
/// cheaply falsifiable without running the full `systemize` pipeline.
fn adl_constraint_violation_blocks(constraint_results: &[ConstraintResult]) -> bool {
    constraint_results
        .iter()
        .any(|result| result.verdict == ConstraintVerdict::Violated)
}

/// Whether any constraint/invariant could not be evaluated (ADR 0007). Blocks admission exactly
/// like a violation -- `Unknown` is never promoted to a pass -- but under its own blocker, so a
/// report distinguishes "a counterexample exists" from "Atlas cannot decide".
fn adl_constraint_unknown_blocks(constraint_results: &[ConstraintResult]) -> bool {
    constraint_results
        .iter()
        .any(|result| result.verdict == ConstraintVerdict::Unknown)
}

/// G130 (ADR 0050): decide every census-quantified invariant over the composed census. The ADL
/// compiler alone leaves them UNKNOWN; every entry point that reads `adl.constraint_results`
/// calls this first, so none of them can disagree about a verdict.
fn decide_census_invariants(inputs: &mut CensusInputs, census: &atlas_core::CensusReport) {
    use atlas_core::composition::{CompositionInput, compose_input, quantified};
    if !quantified::has_census_checks(&inputs.adl) {
        return;
    }
    let model = compose_input(CompositionInput {
        census,
        inventory: &inputs.inventory,
        adl: &inputs.adl,
        dependency_closure: &inputs.dependency_closure,
        revision: &inputs.snapshot.head_sha,
    });
    quantified::apply(&model, &mut inputs.adl);
}

/// Every input `systemize`/`graph`/`code_analyze` need before they can build their own
/// entry-point-specific report: the repository snapshot/audit/inventory/source/docs, compiled ADL,
/// and real `SemanticExtractor` output for the admitted inventory. Extracted as one shared
/// pipeline stage so the three entry points -- each of which independently repeated this exact
/// eight-statement sequence before this fix -- can never silently diverge in how they gather it
/// (e.g. one adding a new admitted-source step the other two forget), the same "shared, not
/// re-derived" discipline already applied to `resolve_repository_id`/`resolve_dependency_closure`
/// above.
struct CensusInputs {
    snapshot: atlas_core::RepositorySnapshot,
    repository: RepoAudit,
    inventory: atlas_core::InventoryReport,
    source: atlas_core::SourceReport,
    docs: DocsReport,
    adl: AdlCompileReport,
    extraction_batches: Vec<adapter::ExtractionBatch>,
    dependency_closure: DependencyClosureReport,
}

impl CensusInputs {
    /// The one place a census is built from gathered inputs: every entry point (`systemize`,
    /// `graph`, `code_analyze`) stamps census-level and ADL facts with the same snapshot revision
    /// its extraction batches carry (G62).
    fn census(&self) -> atlas_core::CensusReport {
        census::build_census(
            &self.inventory,
            &self.source,
            &self.adl,
            &self.extraction_batches,
            &self.snapshot.revision(),
        )
    }
}

fn gather_census_inputs(
    root: &Path,
    cache: Option<&mut census::extraction::ExtractionCache>,
) -> io::Result<CensusInputs> {
    let snapshot = adapter::snapshot_git(root)?;
    let repository = adapter::audit_repository(root)?;
    let inventory = inventory::build_inventory(root, repository.manifest.as_ref())?;
    let source = adapter::source_report_from_inventory(&inventory);
    let docs = adapter::audit_docs(root.join(".atlas"))?;
    let adl_sources = adapter::read_adl_sources(root)?;
    let mut adl = compile_adl(&adl_sources, &source);
    let dependency_closure = resolve_dependency_closure(root)?;
    reconcile_adl_with_dependency_census(&mut adl, &dependency_closure);
    let repository_id = resolve_repository_id(&repository, root);
    let mut extraction_batches = census::extraction::extract_semantics_cached(
        &inventory,
        repository_id,
        snapshot.revision(),
        cache,
    );
    // The second CALL engine (G75): name resolution over the whole workspace, observing the
    // syntactic extractor's CALL claims it resolves.
    let resolution = census::resolution::resolve_rust_path_calls(&inventory, &extraction_batches);
    extraction_batches.extend(resolution);
    // G158: the second CALL engine for TypeScript/JavaScript, linking modules.
    let linked =
        census::typescript_modules::resolve_typescript_modules(&inventory, &extraction_batches);
    extraction_batches.extend(linked);
    Ok(CensusInputs {
        snapshot,
        repository,
        inventory,
        source,
        docs,
        adl,
        extraction_batches,
        dependency_closure,
    })
}

/// ADL consumes census truth (G63, ADR 0026): authored `depends_on` declarations are reconciled
/// against the observed workspace-member dependencies, and the typed results join the ADL's own
/// constraint results -- so a disagreement blocks coding admission exactly like any other failed
/// constraint. Only a CLOSED closure is authoritative: a partial census could omit a real edge
/// and manufacture a declared-not-observed violation, and it already raises its own blocker.
fn reconcile_adl_with_dependency_census(
    adl: &mut AdlCompileReport,
    closure: &DependencyClosureReport,
) {
    if !closure.is_closed() {
        return;
    }
    let observed = atlas_core::ObservedArchitecture::from_closure(closure);
    let reconciliation = atlas_core::reconcile_dependencies(&adl.ir.declared, &observed);
    adl.constraint_results
        .extend(reconciliation.constraint_results());
    adl.deltas.extend(reconciliation.deltas());
}

pub use atlas_core::CENSUS_ADL_PATH;

/// The census-derived ADL for `root` (G63): what the dependency census observes that the
/// authored ADL -- every `.atlas/declared` source except `atlas_core::CENSUS_ADL_PATH` itself --
/// does not declare, and (G137) the effect envelope of every subsystem the authored ADL leaves
/// unbounded. Regenerating it is a fixed point: the envelopes come from a model composed with the
/// authored ADL plus the derived membership, never the committed file. `adl derive --check` and
/// the `census_adl_is_current` test fail when the committed file has drifted from census truth.
pub fn derive_census_adl(root: impl AsRef<Path>) -> io::Result<String> {
    use atlas_core::composition::{CompositionInput, compose_input};
    let root = root.as_ref();
    let mut inputs = gather_census_inputs(root, None)?;
    let authored: Vec<atlas_core::AdlSource> = adapter::read_adl_sources(root)?
        .into_iter()
        .filter(|adl| adl.path != atlas_core::CENSUS_ADL_PATH)
        .collect();
    let closure = &inputs.dependency_closure;
    if !closure.is_closed() {
        return Err(io::Error::other(format!(
            "dependency census is {:?}, not CLOSED: census truth is incomplete, nothing is derived",
            closure.state
        )));
    }
    let declared = compile_adl(&authored, &inputs.source).ir.declared;
    let membership = atlas_core::derive_census_adl(
        &declared,
        &atlas_core::ObservedArchitecture::from_closure(closure),
        &inputs.source,
    );
    let mut sources = authored;
    sources.push(atlas_core::AdlSource {
        path: atlas_core::CENSUS_ADL_PATH.into(),
        text: membership.clone(),
    });
    inputs.adl = compile_adl(&sources, &inputs.source);
    let census = inputs.census();
    let model = compose_input(CompositionInput {
        census: &census,
        inventory: &inputs.inventory,
        adl: &inputs.adl,
        dependency_closure: &inputs.dependency_closure,
        revision: &inputs.snapshot.head_sha,
    });
    Ok(membership + &atlas_core::derive_effect_envelopes(&declared, &model))
}

/// Tests that census the whole repository hold this lock, so at most one such census is
/// resident at a time: several in parallel exceeded the host's memory once the suite grew (G151:
/// the unit obligation of `verification self` was killed by the OOM killer at 12.8 GB).
#[cfg(test)]
pub(crate) fn whole_repo_census_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

pub fn systemize(root: impl AsRef<Path>) -> io::Result<SystemizeReport> {
    systemize_since(root, None)
}

/// The `inventory` of an earlier `systemize --out` report, the baseline for `systemize_since`.
pub fn read_previous_inventory(path: impl AsRef<Path>) -> io::Result<InventoryReport> {
    let invalid = |message: String| io::Error::new(io::ErrorKind::InvalidData, message);
    let text = std::fs::read_to_string(path)?;
    let mut report: serde_json::Value =
        serde_json::from_str(&text).map_err(|e| invalid(e.to_string()))?;
    let inventory = report
        .get_mut("inventory")
        .map(serde_json::Value::take)
        .ok_or_else(|| invalid("not a systemize report (no `inventory`)".into()))?;
    serde_json::from_value(inventory).map_err(|e| invalid(format!("inventory: {e}")))
}

/// `systemize`, plus inventory change detection against `previous` -- the inventory of an earlier
/// systemize run over the same root (ADR 0006). A baseline that cannot be diffed (another root,
/// another inventory schema, duplicate paths) is an error, never a silently empty delta.
pub fn systemize_since(
    root: impl AsRef<Path>,
    previous: Option<&InventoryReport>,
) -> io::Result<SystemizeReport> {
    systemize_with(root, previous, None)
}

/// `systemize_since`, serving per-artifact semantic extraction through `cache` when supplied
/// (ADR 0008). The report is identical to an uncached run's except for `extraction_cache`.
pub fn systemize_with(
    root: impl AsRef<Path>,
    previous: Option<&InventoryReport>,
    mut cache: Option<&mut census::extraction::ExtractionCache>,
) -> io::Result<SystemizeReport> {
    let root = root.as_ref();
    let mut inputs = gather_census_inputs(root, cache.as_deref_mut())?;
    let mut census = inputs.census();
    decide_census_invariants(&mut inputs, &census);
    let CensusInputs {
        snapshot,
        repository,
        inventory,
        source,
        docs,
        adl,
        extraction_batches,
        dependency_closure,
    } = inputs;

    // R4.3.1: semantic extraction runs BEFORE census construction, and its results flow directly
    // into the canonical `CensusReport` that `normalize`/`graph` below then consume -- extraction
    // is no longer a post-census accounting-only sidecar
    // (`.atlas/contracts/SEMANTIC-EXTRACTION.md`: "Census -> Normalize -> Reconcile -> Engineering
    // Graph" is the one normalized path). `extraction_accounting` and `census` are both built from
    // the exact same `extraction_batches`, so closure accounting and canonical census truth can
    // never disagree about what extraction produced (`census` is `CensusInputs::census` above).
    let mut extraction_accounting = census::CensusExtractionAccounting::new();
    for batch in &extraction_batches {
        extraction_accounting.record_batch(batch);
    }

    let normalization = normalize::normalize(&census);

    // `.atlas/contracts/DEPENDENCY-CENSUS.md`: census does not stop at the repository boundary.
    // `BUILD` starts life as a permanent `Unsupported` stub in `census::build_census` (an
    // accounting axis outside the R4 semantic dimension set, computed with no filesystem access);
    // promote it to real evidence here now that a real, closed Cargo dependency closure exists.
    // Computed before `graph` below so the resolved edges can be projected into it
    // (`DEPENDENCY-CENSUS.md`: "the dependency graph is part of canonical census truth... feeds
    // query, graph, security..." -- previously `dependency_closure` reached only this report's own
    // sibling field, never `EngineeringGraph` itself).
    let inventory_delta = previous
        .map(|previous| diff_inventories(previous, &inventory))
        .transpose()
        .map_err(|refusal| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("previous inventory: {refusal}"),
            )
        })?;
    let graph = summarize_system_graph_with_dependencies(
        &source,
        &docs,
        &normalization,
        &dependency_closure,
        &adl.constraint_results,
    );
    // `NotApplicable` (no Cargo.lock at all -- e.g. a non-Rust admitted repository) is not a
    // failure and leaves `BUILD` at whatever `census::build_census` already set (`Unsupported`):
    // this ecosystem was never observed here, not incompletely observed. Only `Partial`/`Blocked`
    // (a real Cargo workspace census actually attempted and failed to fully close) demote `BUILD`
    // to `Unknown` and raise a coding-admission blocker.
    let (build_status, dependency_closure_blocks) =
        build_coverage_from_dependency_closure(dependency_closure.state);
    if let Some(status) = build_status {
        census.coverage.insert("BUILD".into(), status);
    }

    let mut blockers = Vec::new();
    if !repository.ready {
        blockers.push("REPO_GATE_NOT_READY".to_owned());
    }
    if !docs.gate_ready {
        blockers.push("DOCS_GATE_NOT_READY".to_owned());
    }
    if !adl.diagnostics.is_empty() {
        blockers.push("ADL_DIAGNOSTICS_PRESENT".to_owned());
    }
    if adl_constraint_violation_blocks(&adl.constraint_results) {
        blockers.push("ADL_CONSTRAINT_VIOLATED".to_owned());
    }
    if adl_constraint_unknown_blocks(&adl.constraint_results) {
        blockers.push("ADL_CONSTRAINT_UNKNOWN".to_owned());
    }
    if !inventory.is_closed() {
        blockers.push("INVENTORY_ACCOUNTING_NOT_CLOSED".to_owned());
    }
    if !census.is_closed() {
        blockers.push("CENSUS_ACCOUNTING_NOT_CLOSED".to_owned());
    }
    if !normalization.is_closed() {
        blockers.push("NORMALIZATION_ACCOUNTING_NOT_CLOSED".to_owned());
    }
    if !extraction_accounting.is_closed_per_extractor(census::extraction::requested_dimensions) {
        blockers.push("SEMANTIC_EXTRACTION_ACCOUNTING_NOT_CLOSED".to_owned());
    }
    // `NotApplicable` never blocks: absence of a Cargo workspace at this root is not itself a
    // failure (see `build_coverage_from_dependency_closure` above). Only an actually-attempted-
    // but-incomplete Cargo census (`Partial`/`Blocked`) withholds coding admission.
    if dependency_closure_blocks {
        blockers.push("DEPENDENCY_CLOSURE_NOT_CLOSED".to_owned());
    }

    Ok(SystemizeReport {
        schema: "atlas.systemizer.systemize-report.v14".into(),
        cli_api: CLI_API.into(),
        root: root.canonicalize()?.to_string_lossy().into_owned(),
        snapshot,
        repository,
        docs: docs.clone(),
        adl,
        coding_admission: CodingAdmission {
            schema: "atlas.systemizer.coding-admission.v1".into(),
            allowed: blockers.is_empty(),
            docs_standard: docs.standard,
            blockers,
        },
        inventory,
        source,
        census,
        normalization,
        graph,
        dependency_closure,
        inventory_delta,
        extraction_cache: cache.map(|cache| cache.stats().clone()),
        invariants: vec![
            "CANONICAL_REPOSITORY_KNOWLEDGE_IS_IN_ATLAS_ROOT".into(),
            "FACTS_COMPILE_TO_ONE_ENGINEERING_GRAPH".into(),
            "GRAPH_BEFORE_CODE".into(),
            "EXACT_BASE_SHA_REQUIRED".into(),
            "ONE_CANONICAL_TARGET_PER_WORKRUN".into(),
            "DONORS_ARE_REFERENCE_AND_EVIDENCE_NOT_RUNTIME_OWNERS".into(),
            "INVENTORY_PRECEDES_SEMANTIC_DEPTH".into(),
            "UNKNOWN_OR_OVERSIZED_ARTIFACTS_CANNOT_DISAPPEAR".into(),
            "CENSUS_PRECEDES_NORMALIZATION".into(),
            "NORMALIZATION_PRESERVES_PROVENANCE".into(),
            "NORMALIZATION_MUST_NOT_DROP_CENSUS_FACTS".into(),
            "ENGINEERING_GRAPH_IS_PROJECTION_OF_NORMALIZED_FACTS".into(),
            "UNSUPPORTED_SEMANTIC_DIMENSIONS_ARE_EXPLICIT".into(),
            "SEMANTIC_EXTRACTION_NEVER_FABRICATES_COMPILER_RESOLVED_SEMANTICS".into(),
            "AI_OUTPUT_IS_PROPOSAL_NOT_CANONICAL_TRUTH".into(),
            "DEPENDENCY_CLOSURE_IS_CANONICAL_CENSUS_TRUTH".into(),
        ],
    })
}

pub fn check(root: impl AsRef<Path>) -> io::Result<AdlCompileReport> {
    let root = root.as_ref();
    let repository = adapter::audit_repository(root)?;
    let source = match repository.manifest.as_ref() {
        Some(manifest) => adapter::scan_declared_source(root, manifest)?,
        None => adapter::scan_source(root)?,
    };
    let adl_sources = adapter::read_adl_sources(root)?;
    Ok(compile_adl(&adl_sources, &source))
}

pub fn graph(root: impl AsRef<Path>) -> io::Result<EngineeringGraph> {
    let root = root.as_ref();
    let mut inputs = gather_census_inputs(root, None)?;
    let census = inputs.census();
    decide_census_invariants(&mut inputs, &census);
    let CensusInputs {
        source,
        docs,
        adl,
        dependency_closure,
        ..
    } = inputs;
    let normalization = normalize::normalize(&census);
    let mut graph = build_system_graph(&source, &docs, &normalization);
    add_constraint_derivations(&mut graph, &adl.constraint_results);
    add_dependency_closure(&mut graph, &dependency_closure);
    Ok(graph)
}

pub fn contract() -> Contract {
    Contract::default()
}

pub fn docs_audit(root: impl AsRef<Path>) -> io::Result<DocsReport> {
    adapter::audit_docs(root)
}

pub fn code_analyze(root: impl AsRef<Path>) -> io::Result<serde_json::Value> {
    let root = root.as_ref();
    let mut inputs = gather_census_inputs(root, None)?;
    let mut census = inputs.census();
    decide_census_invariants(&mut inputs, &census);
    let CensusInputs {
        inventory,
        source,
        docs,
        adl,
        dependency_closure,
        ..
    } = inputs;
    // Same promotion `systemize` applies (`.atlas/contracts/DEPENDENCY-CENSUS.md`): `BUILD`
    // starts life as a permanent `Unsupported` stub in `census::build_census` and must be
    // promoted to real evidence once a real, closed Cargo dependency closure exists -- otherwise
    // `code_analyze`'s own `census.coverage.BUILD` silently disagrees with the `dependency_closure`
    // this same response reports two fields below, contradicting real, observed state.
    let (build_status, _) = build_coverage_from_dependency_closure(dependency_closure.state);
    if let Some(status) = build_status {
        census.coverage.insert("BUILD".into(), status);
    }
    let normalization = normalize::normalize(&census);
    let graph = summarize_system_graph_with_dependencies(
        &source,
        &docs,
        &normalization,
        &dependency_closure,
        &adl.constraint_results,
    );

    Ok(serde_json::json!({
        "schema": "atlas.systemizer.code-analysis.v3",
        "inventory": inventory,
        "source": source,
        "adl": adl,
        "census": census,
        "normalization": normalization,
        "dependency_closure": dependency_closure,
        "graph": graph,
        "source_of_truth": "derived engineering analysis; target repositories remain sovereign"
    }))
}

pub fn parse(root: impl AsRef<Path>) -> io::Result<Vec<AdlProgram>> {
    let sources = adapter::read_adl_sources(root)?;
    Ok(sources.iter().map(parse_adl_source).collect())
}

/// The exact command set the repository's own CI gate (`.github/workflows/ci.yml`) enforces on
/// every push/PR, in the order CI runs them. `WorkRequest.required_verification` must stay a
/// superset of this list: a candidate that only satisfies a weaker local list could pass
/// `prepare_work`'s admission and still fail CI, which is exactly the gap this closes (CI already
/// runs `cargo clippy --workspace --all-targets -- -D warnings`, but this list previously omitted
/// it and would have let a lint-violating candidate look admissible).
fn required_verification_commands() -> Vec<String> {
    vec![
        "cargo fmt --all --check".into(),
        "cargo clippy --workspace --all-targets -- -D warnings".into(),
        "cargo test --workspace".into(),
        "atlas-systemizer systemize".into(),
    ]
}

pub fn prepare_work(
    root: impl AsRef<Path>,
    goal: impl Into<String>,
    expected_base_sha: Option<String>,
) -> io::Result<WorkPrepareReport> {
    let root = root.as_ref();
    let system = systemize(root)?;
    let base_revision = RevisionRef {
        kind: "git".into(),
        value: system.snapshot.head_sha.clone(),
    };
    let mut blockers = system.coding_admission.blockers.clone();

    if let Some(expected) = expected_base_sha
        && expected != system.snapshot.head_sha
    {
        blockers.push(format!(
            "BASE_SHA_DRIFT expected {expected} but checkout is {}",
            system.snapshot.head_sha
        ));
    }
    if system.snapshot.dirty {
        blockers.push("WORKTREE_HAS_UNCOMMITTED_CHANGES".into());
    }

    let request = WorkRequest {
        schema: "atlas.work-request.v1".into(),
        repository: system.root.clone(),
        base_revision: base_revision.clone(),
        goal: goal.into(),
        scope: vec!["single-repository".into()],
        allowed_paths: work_allowed_paths(system.repository.manifest.as_ref()),
        forbidden_paths: vec![
            ".atlas/temporary".into(),
            ".atlas/provenance".into(),
            ".atlas/licenses".into(),
        ],
        required_verification: required_verification_commands(),
    };

    let allowed = blockers.is_empty();
    Ok(WorkPrepareReport {
        schema: "atlas.work-prepare-report.v1".into(),
        request,
        repository: system.repository,
        snapshot: system.snapshot.clone(),
        graph: system.graph,
        coding_admission: system.coding_admission,
        allowed,
        blockers,
        evidence: vec![Evidence {
            id: "evidence:work-prepare:git-head".into(),
            kind: "RepositorySnapshot".into(),
            path: system.root,
            summary: format!(
                "Prepared work against exact Git revision {}",
                base_revision.value
            ),
            revision: Some(base_revision),
        }],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use atlas_core::{DependencyClosureState, EpistemicStatus};

    // `.atlas/contracts/DEPENDENCY-CENSUS.md`: BUILD coverage/coding-admission must derive from
    // evidence state, not default structure values. One falsification case per state transition.

    #[test]
    fn not_applicable_promotes_no_coverage_and_never_blocks() {
        let (status, blocks) =
            build_coverage_from_dependency_closure(DependencyClosureState::NotApplicable);
        assert_eq!(status, None);
        assert!(
            !blocks,
            "a repository with no Cargo workspace at all must not be treated as a failed dependency census"
        );
    }

    #[test]
    fn closed_promotes_build_to_observed_and_never_blocks() {
        let (status, blocks) =
            build_coverage_from_dependency_closure(DependencyClosureState::Closed);
        assert_eq!(status, Some(EpistemicStatus::Observed));
        assert!(!blocks);
    }

    #[test]
    fn partial_demotes_build_to_unknown_and_blocks() {
        let (status, blocks) =
            build_coverage_from_dependency_closure(DependencyClosureState::Partial);
        assert_eq!(status, Some(EpistemicStatus::Unknown));
        assert!(blocks);
    }

    #[test]
    fn blocked_demotes_build_to_unknown_and_blocks() {
        let (status, blocks) =
            build_coverage_from_dependency_closure(DependencyClosureState::Blocked);
        assert_eq!(status, Some(EpistemicStatus::Unknown));
        assert!(
            blocks,
            "a present but unparseable Cargo.lock must not be treated as a closed dependency census"
        );
    }

    #[test]
    fn not_applicable_and_closed_are_never_conflated() {
        // The exact regression this module's helper replaces: both states previously produced
        // `is_closed() == true` from a fabricated zero-edge report, making a repository with no
        // Cargo workspace indistinguishable from one with a genuinely verified empty closure.
        let (not_applicable_status, not_applicable_blocks) =
            build_coverage_from_dependency_closure(DependencyClosureState::NotApplicable);
        let (closed_status, closed_blocks) =
            build_coverage_from_dependency_closure(DependencyClosureState::Closed);
        assert_ne!(not_applicable_status, closed_status);
        assert_eq!(
            not_applicable_blocks, closed_blocks,
            "neither blocks, but for different reasons"
        );
    }

    fn manifest_with_roots(
        source_roots: Vec<&str>,
        backend_roots: Vec<&str>,
        frontend_roots: Vec<&str>,
        test_roots: Vec<&str>,
    ) -> RepoManifest {
        RepoManifest {
            schema: "atlas.repo.v2".into(),
            repo: "org/repo".into(),
            system_kind: "SYSTEM_INVENTION_FORGE".into(),
            backend_language: "rust".into(),
            frontend_language: "typescript".into(),
            coding_requires_docs_gate: true,
            graph_before_code_required: true,
            exact_base_sha_required: true,
            single_repository_target_required: true,
            knowledge_root: ".atlas".into(),
            temporary_root: ".atlas/temporary".into(),
            provenance_root: ".atlas/provenance".into(),
            license_root: ".atlas/licenses".into(),
            source_roots: source_roots.into_iter().map(String::from).collect(),
            backend_roots: backend_roots.into_iter().map(String::from).collect(),
            frontend_roots: frontend_roots.into_iter().map(String::from).collect(),
            test_roots: test_roots.into_iter().map(String::from).collect(),
        }
    }

    #[test]
    fn work_allowed_paths_includes_backend_roots_not_covered_by_any_other_field() {
        // The exact regression this function's own extraction fixes: `backend_roots` was declared
        // in the manifest schema, validated for path-escape, and documented
        // (`.atlas/contracts/EXTERNAL-PROVIDER-TRUST.md#capability-minimum`) as one of the four
        // fields joined into the filesystem walk / capability scope -- but silently never actually
        // included here, so a `backend_roots` entry not already covered by `source_roots`/
        // `frontend_roots`/`test_roots` granted an external provider zero capability to touch
        // legitimate, admitted repository source.
        let manifest = manifest_with_roots(vec!["shared"], vec!["services/api"], vec![], vec![]);
        let paths = work_allowed_paths(Some(&manifest));
        assert!(
            paths.iter().any(|path| path == "services/api"),
            "a backend_roots entry not covered by any other field must appear in allowed_paths: {paths:?}"
        );
    }

    #[test]
    fn work_allowed_paths_unions_all_four_fields_deduplicated_and_sorted() {
        let manifest = manifest_with_roots(
            vec!["core", "shared"],
            vec!["shared"],
            vec!["apps/web"],
            vec!["core/tests"],
        );
        let paths = work_allowed_paths(Some(&manifest));
        assert_eq!(
            paths,
            vec![
                "apps/web".to_owned(),
                "core".to_owned(),
                "core/tests".to_owned(),
                "shared".to_owned(),
            ],
            "a root declared in both source_roots and backend_roots must appear exactly once"
        );
    }

    #[test]
    fn work_allowed_paths_filters_an_escaping_backend_root() {
        let manifest = manifest_with_roots(vec![], vec!["../outside"], vec![], vec![]);
        let paths = work_allowed_paths(Some(&manifest));
        assert!(
            paths.is_empty(),
            "an escaping backend_roots entry must never reach allowed_paths: {paths:?}"
        );
    }

    #[test]
    fn work_allowed_paths_with_no_manifest_is_empty() {
        assert!(work_allowed_paths(None).is_empty());
    }

    // `.github/workflows/ci.yml` is the repository's real, authoritative CI gate. This is a
    // direct, file-based falsification: it reads the actual CI workflow rather than re-asserting
    // a hardcoded expectation, so it cannot silently drift the way the previous omission did
    // (required_verification was missing the clippy command CI has run all along).
    #[test]
    fn required_verification_commands_cover_every_command_ci_runs() {
        let ci_yaml = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.github/workflows/ci.yml"),
        )
        .expect("repository's CI workflow file must exist and be readable");

        let ci_commands: Vec<&str> = ci_yaml
            .lines()
            .filter_map(|line| line.trim().strip_prefix("- run: cargo "))
            .map(|rest| rest.trim())
            .collect();
        assert!(
            !ci_commands.is_empty(),
            "expected to find at least one `- run: cargo ...` step in ci.yml; the parsing above \
             may have drifted from the workflow file's actual format"
        );

        let required = required_verification_commands();
        for ci_command in ci_commands {
            let full_command = format!("cargo {ci_command}");
            assert!(
                required.iter().any(|r| r == &full_command),
                "CI runs `{full_command}` but WorkRequest.required_verification does not \
                 require it -- a candidate could pass prepare_work's admission and still fail CI"
            );
        }
    }

    // `.atlas/contracts/cli/atlas-systemizer-cli-v1.json` is a machine-readable JSON Schema
    // describing this binary's own stable CLI surface -- but nothing in this workspace ever
    // validated the real CLI against it, so it silently drifted: it named a `"fleet connect"`
    // subcommand that has never existed in this codebase, was missing three real subcommands
    // (`check`/`graph`/`parse`), and named the wrong `subsystem_kind` -- the exact inversion a
    // "stable CLI contract" exists to prevent (a schema validator built against the stale file
    // would reject real, working subcommands while accepting a phantom one). Corrected the file's
    // content and added this permanent check so it can never drift unnoticed again.
    #[test]
    fn cli_contract_json_matches_the_real_contract_default() {
        let contract_text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../.atlas/contracts/cli/atlas-systemizer-cli-v1.json"),
        )
        .expect(".atlas/contracts/cli/atlas-systemizer-cli-v1.json must exist and be readable");
        let schema: serde_json::Value =
            serde_json::from_str(&contract_text).expect("the CLI contract must be valid JSON");

        let real = Contract::default();

        assert_eq!(
            schema["properties"]["schema"]["const"].as_str(),
            Some(real.schema.as_str())
        );
        assert_eq!(
            schema["properties"]["binary"]["const"].as_str(),
            Some(real.binary.as_str())
        );
        assert_eq!(
            schema["properties"]["subsystem_kind"]["const"].as_str(),
            Some(real.subsystem_kind.as_str()),
            "the contract's declared subsystem_kind must match Contract::default()'s real value"
        );
        assert_eq!(
            schema["properties"]["runtime_dependency_allowed"]["const"].as_bool(),
            Some(real.runtime_dependency_allowed)
        );

        let declared_commands: std::collections::BTreeSet<String> =
            schema["properties"]["commands"]["items"]["enum"]
                .as_array()
                .expect("commands.items.enum must be a JSON array")
                .iter()
                .map(|value| {
                    value
                        .as_str()
                        .expect("every command must be a string")
                        .to_owned()
                })
                .collect();
        let real_commands: std::collections::BTreeSet<String> = real.commands.into_iter().collect();
        assert_eq!(
            declared_commands, real_commands,
            "the CLI contract's declared command set must exactly match the real \
             Contract::default() command set -- a subcommand present in one but not the other is \
             exactly the drift this permanent check exists to catch"
        );
    }

    // `.atlas/evidence/verification/duplicate-classification-logic-swept-clean.json`: five
    // separate instances of the same defect class -- a small classification/helper function
    // copy-pasted into a second file (sometimes under a different name), with nothing to stop the
    // two copies silently drifting apart on a future edit to only one -- were found and fixed by a
    // one-off script this session. This test formalizes that script as a permanent, rerunning
    // regression check, per `.atlas/contracts/RECURSIVE-SELF-CENSUS.md`'s own preference for
    // machine-readable, durable evidence over a script that runs once and is discarded.
    //
    // Extracts every top-level `fn`'s brace-matched body from every `.rs` file in the four
    // workspace crates (skipping file names containing "test" and everything from a file's first
    // `#[cfg(test)]` onward, so real test fixtures/corpora are never flagged), normalizes
    // whitespace, and fails if any exact body text (long enough to be a real finding, not a
    // trivial one-liner) appears in more than one file. Deliberately coarse and over-inclusive in
    // one direction only: a byte-matching brace counter can be confused by an unbalanced brace
    // inside a string/comment, but this repository's own source has none (verified: this test
    // currently passes cleanly), and any future false positive is a loud, investigable test
    // failure, never a silent miss.
    mod duplicate_function_body_sweep {
        use std::path::{Path, PathBuf};

        fn workspace_root() -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .canonicalize()
                .expect("workspace root must exist")
        }

        fn rust_files_under(dir: &Path, out: &mut Vec<PathBuf>) {
            let Ok(entries) = std::fs::read_dir(dir) else {
                return;
            };
            let mut entries: Vec<_> = entries.filter_map(Result::ok).collect();
            entries.sort_by_key(|entry| entry.file_name());
            for entry in entries {
                let path = entry.path();
                let Ok(file_type) = entry.file_type() else {
                    continue;
                };
                if file_type.is_dir() {
                    rust_files_under(&path, out);
                } else if path.extension().and_then(|ext| ext.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        /// Every top-level `fn <name> ... { ... }` body in `text` (brace-matched from the first
        /// `{` after the `fn` keyword), whitespace-normalized to a single-spaced string. Only
        /// scans up to `text`'s first `#[cfg(test)]` occurrence, if any.
        fn top_level_fn_bodies(text: &str) -> Vec<String> {
            let scan_end = text.find("#[cfg(test)]").unwrap_or(text.len());
            let scan_text = &text[..scan_end];
            let bytes = scan_text.as_bytes();
            let mut bodies = Vec::new();
            let mut index = 0;
            while let Some(offset) = scan_text[index..].find("fn ") {
                let fn_at = index + offset;
                // Require a preceding word boundary so this never matches inside an identifier
                // merely ending in "fn " (e.g. none realistically exist, but stay precise).
                let boundary_ok = fn_at == 0
                    || !bytes[fn_at - 1].is_ascii_alphanumeric() && bytes[fn_at - 1] != b'_';
                let Some(brace_start) = scan_text[fn_at..].find('{') else {
                    break;
                };
                let brace_start = fn_at + brace_start;
                // A `;` before the first `{` means this "fn " was a trait method signature with
                // no body, or occurred inside a type/string this scan doesn't need to handle
                // specially -- either way, skip past it without counting a body.
                let semi_before_brace = scan_text[fn_at..brace_start].find(';');
                if !boundary_ok || semi_before_brace.is_some() {
                    index = fn_at + 3;
                    continue;
                }
                let mut depth = 0usize;
                let mut i = brace_start;
                while i < bytes.len() {
                    match bytes[i] {
                        b'{' => depth += 1,
                        b'}' => {
                            depth -= 1;
                            if depth == 0 {
                                break;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
                if depth == 0 && i < bytes.len() {
                    let body = &scan_text[brace_start..=i];
                    let normalized = body.split_whitespace().collect::<Vec<_>>().join(" ");
                    if normalized.len() >= 60 {
                        bodies.push(normalized);
                    }
                    index = i + 1;
                } else {
                    // Unbalanced (should not happen for real Rust source) -- stop scanning this
                    // file rather than loop on a broken byte offset.
                    break;
                }
            }
            bodies
        }

        /// Exact, whitespace-normalized function bodies this sweep must NOT flag, each with its
        /// own justification -- deliberately narrow (an exact string match, not a pattern), so a
        /// future edit that changes the body even slightly makes the exemption stop matching and
        /// the sweep re-evaluate that spot fresh, rather than silently widening what it excuses.
        ///
        /// Unlike every real finding this sweep and its predecessor script already found and
        /// fixed this session (a classification/dispatch function accidentally copy-pasted into a
        /// second file), this one entry is a *coincidental* shape match between four independently
        /// meaningful concepts, not an accidental duplication of one concept:
        /// `DataFlowResolution`/`OwnershipResolution`/`PersistenceResolution`/`StateResolution`
        /// (`core::semantic::{data_flow,ownership,persistence,state}`) each document their own,
        /// genuinely different, dimension-specific meaning of "Resolved"/"Unresolved" in their own
        /// per-variant doc comments -- merging them into one shared type would trade away real
        /// type safety (today, passing an `OwnershipResolution` where a `DataFlowResolution` is
        /// expected is a compile error; a shared type would make that a silent, valid conversion)
        /// for a purely cosmetic reduction of a trivial two-arm `as_str` match, which is a much
        /// worse trade than the real fixes this sweep already produced.
        const KNOWN_ACCEPTABLE_DUPLICATE_BODIES: &[&str] = &[
            "{ match self { Self::Resolved => \"RESOLVED\", Self::Unresolved => \"UNRESOLVED\", } }",
        ];

        #[test]
        fn no_function_body_is_duplicated_verbatim_across_two_workspace_source_files() {
            let root = workspace_root();
            let mut files = Vec::new();
            for crate_dir in ["core/src", "adapter/src", "runtime/src", "apps/cli/src"] {
                rust_files_under(&root.join(crate_dir), &mut files);
            }
            assert!(
                files.len() > 20,
                "expected to find real source files under the workspace root {root:?}; found {}",
                files.len()
            );

            let mut bodies_by_text: std::collections::BTreeMap<String, Vec<PathBuf>> =
                std::collections::BTreeMap::new();
            for path in &files {
                if path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.contains("test"))
                {
                    continue;
                }
                let Ok(text) = std::fs::read_to_string(path) else {
                    continue;
                };
                for body in top_level_fn_bodies(&text) {
                    bodies_by_text.entry(body).or_default().push(path.clone());
                }
            }

            let mut violations = Vec::new();
            for (body, paths) in &bodies_by_text {
                if KNOWN_ACCEPTABLE_DUPLICATE_BODIES.contains(&body.as_str()) {
                    continue;
                }
                let unique_files: std::collections::BTreeSet<&PathBuf> = paths.iter().collect();
                if unique_files.len() > 1 {
                    violations.push(format!(
                        "identical function body appears in {} different files: {:?}\nbody: {}",
                        unique_files.len(),
                        unique_files,
                        &body[..body.len().min(160)]
                    ));
                }
            }
            assert!(
                violations.is_empty(),
                "found duplicated function bodies across workspace source files -- extract a \
                 shared function/method instead, per this session's own established fix pattern \
                 (see .atlas/evidence/verification/duplicate-classification-logic-swept-clean.json):\n\n{}",
                violations.join("\n\n")
            );
        }
    }

    // `.atlas/references/donor-corpus.toml` is this repository's own canonical donor tracker
    // (58 records at G118), consulted and hand-edited repeatedly across this session's
    // donor-research generations. Every edit was verified ad hoc with a one-off
    // `python3 -c "import tomllib; ..."` shell command re-run by hand each time -- exactly the
    // "self-hosting pressure" this repository's own roadmap names: a script that runs once and is
    // discarded, per `.atlas/contracts/RECURSIVE-SELF-CENSUS.md`'s preference for durable,
    // machine-readable, permanently-rerunning evidence instead. This formalizes that check as a
    // real, permanent regression test, hand-parsed (no `toml` crate dependency exists anywhere in
    // this workspace, matching `adapter::dependency::cargo`'s own hand-rolled parsing precedent
    // rather than adding a new dependency for test-only use) rather than pulled in fresh.
    mod donor_corpus_integrity {
        use std::path::{Path, PathBuf};

        fn workspace_root() -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .canonicalize()
                .expect("workspace root must exist")
        }

        struct DonorEntry {
            id: String,
            evidence: Vec<String>,
            license: Vec<String>,
            census_status: String,
            decision_status: String,
            ingestion_status: String,
        }

        /// Hand-rolled, deliberately narrow parse: extracts only the first `id = "..."` line and
        /// the `evidence = [...]` line (confirmed single-line for every one of this file's current
        /// 58 entries) within each `[[donor]]` block. Does not attempt to parse TOML in general --
        /// exactly the same scope discipline `adapter::dependency::cargo`'s own hand-rolled parser
        /// already applies to `Cargo.lock`/`Cargo.toml`.
        /// Appends every `"..."` quoted substring found in `s` to `out`.
        fn extract_quoted_strings(s: &str, out: &mut Vec<String>) {
            let bytes = s.as_bytes();
            let mut index = 0;
            while index < bytes.len() {
                if bytes[index] == b'"' {
                    if let Some(end) = s[index + 1..].find('"') {
                        out.push(s[index + 1..index + 1 + end].to_owned());
                        index = index + 1 + end + 1;
                    } else {
                        break;
                    }
                } else {
                    index += 1;
                }
            }
        }

        /// Consumes a `key = [...]` array starting at `lines[i]` (already confirmed to start with
        /// `prefix`), which may be single-line (the common case) or span multiple lines -- one
        /// quoted path per line, closed by a bare `]` -- like the `zed`/`evidence` and
        /// `zed`/`license` entries' own arrays. Returns the parsed paths and the index of the line
        /// after the array's close.
        fn parse_quoted_array(lines: &[&str], i: usize, rest: &str) -> (Vec<String>, usize) {
            let mut paths = Vec::new();
            extract_quoted_strings(rest, &mut paths);
            let mut closed = rest.contains(']');
            let mut j = i;
            while !closed && j + 1 < lines.len() {
                j += 1;
                let next = lines[j].trim();
                extract_quoted_strings(next, &mut paths);
                closed = next.contains(']');
            }
            (paths, j + 1)
        }

        fn parse_donor_corpus(text: &str) -> Vec<DonorEntry> {
            let mut entries = Vec::new();
            let mut current_id: Option<String> = None;
            let mut current_evidence: Vec<String> = Vec::new();
            let mut current_license: Vec<String> = Vec::new();
            let mut current_census_status = String::new();
            let mut current_ingestion_status = String::new();
            let mut current_decision_status = String::new();
            let mut in_block = false;

            let lines: Vec<&str> = text.lines().collect();
            let mut i = 0;
            while i < lines.len() {
                let trimmed = lines[i].trim();
                if trimmed == "[[donor]]" {
                    if let Some(id) = current_id.take() {
                        entries.push(DonorEntry {
                            id,
                            evidence: std::mem::take(&mut current_evidence),
                            license: std::mem::take(&mut current_license),
                            census_status: std::mem::take(&mut current_census_status),
                            ingestion_status: std::mem::take(&mut current_ingestion_status),
                            decision_status: std::mem::take(&mut current_decision_status),
                        });
                    }
                    in_block = true;
                    i += 1;
                    continue;
                }
                if !in_block {
                    i += 1;
                    continue;
                }
                if current_id.is_none()
                    && let Some(rest) = trimmed.strip_prefix("id = \"")
                    && let Some(end) = rest.find('"')
                {
                    current_id = Some(rest[..end].to_owned());
                    i += 1;
                    continue;
                }
                if let Some(rest) = trimmed.strip_prefix("ingestion_status = \"")
                    && let Some(end) = rest.find('"')
                {
                    current_ingestion_status = rest[..end].to_owned();
                    i += 1;
                    continue;
                }
                if let Some(rest) = trimmed.strip_prefix("census_status = \"")
                    && let Some(end) = rest.find('"')
                {
                    current_census_status = rest[..end].to_owned();
                    i += 1;
                    continue;
                }
                if let Some(rest) = trimmed.strip_prefix("decision_status = \"")
                    && let Some(end) = rest.find('"')
                {
                    current_decision_status = rest[..end].to_owned();
                    i += 1;
                    continue;
                }
                if let Some(rest) = trimmed.strip_prefix("evidence = [") {
                    let (paths, next_i) = parse_quoted_array(&lines, i, rest);
                    current_evidence = paths;
                    i = next_i;
                    continue;
                }
                // `license` is declared two ways across this file: an array of real, vendored
                // license-file paths (most donors, checked below), or a bare SPDX identifier
                // string (`license = "MIT"`, a label only, no file to verify) for donors recorded
                // without vendored license files. Only the array form is parsed here; the bare
                // string form is intentionally left unhandled (it falls through to the final
                // `i += 1` below) -- there is no path to check, and misreading it as a path list
                // would fabricate evidence this parser cannot verify.
                if let Some(rest) = trimmed.strip_prefix("license = [") {
                    let (paths, next_i) = parse_quoted_array(&lines, i, rest);
                    current_license = paths;
                    i = next_i;
                    continue;
                }
                i += 1;
            }
            if let Some(id) = current_id.take() {
                entries.push(DonorEntry {
                    id,
                    evidence: current_evidence,
                    license: current_license,
                    census_status: current_census_status,
                    ingestion_status: current_ingestion_status,
                    decision_status: current_decision_status,
                });
            }
            entries
        }

        fn load_entries() -> Vec<DonorEntry> {
            let root = workspace_root();
            let text = std::fs::read_to_string(root.join(".atlas/references/donor-corpus.toml"))
                .expect("donor-corpus.toml must exist and be readable");
            let block_count = text
                .lines()
                .filter(|line| line.trim() == "[[donor]]")
                .count();
            let entries = parse_donor_corpus(&text);
            assert_eq!(
                entries.len(),
                block_count,
                "parser found {} DonorEntry values but the file has {} [[donor]] blocks -- the \
                 hand-rolled parser above has drifted from the file's actual format",
                entries.len(),
                block_count
            );
            entries
        }

        #[test]
        fn every_donor_has_a_unique_id() {
            let entries = load_entries();
            let mut seen = std::collections::HashSet::new();
            for entry in &entries {
                assert!(
                    !entry.id.is_empty(),
                    "a [[donor]] block has an empty or missing id"
                );
                assert!(
                    seen.insert(entry.id.clone()),
                    "duplicate donor id `{}` in donor-corpus.toml",
                    entry.id
                );
            }
        }

        #[test]
        fn every_donor_has_at_least_one_evidence_path_and_every_path_exists() {
            let root = workspace_root();
            let entries = load_entries();
            for entry in &entries {
                assert!(
                    !entry.evidence.is_empty(),
                    "donor `{}` has no evidence array -- every donor must cite at least one real \
                     evidence file (a census/provenance/genome record), never bare assertion",
                    entry.id
                );
                for path in &entry.evidence {
                    assert!(
                        root.join(path).exists(),
                        "donor `{}`'s evidence path `{}` does not exist on disk -- a dangling \
                         evidence reference is exactly the kind of unverifiable claim this \
                         repository's own donor-absorption discipline forbids",
                        entry.id,
                        path
                    );
                }
            }
        }

        /// The same dangling-reference discipline `every_donor_has_at_least_one_evidence_path_
        /// and_every_path_exists` already applies to `evidence`, applied to `license` -- a
        /// real, separate legal/provenance obligation (`.atlas/licenses/`), not previously checked
        /// at all: `DonorEntry` had no `license` field until this generation. Only the array-of-
        /// file-paths form is checked here (most donors); a bare SPDX-string `license = "MIT"`
        /// entry has no file path to verify and is correctly excluded by the parser itself, not
        /// silently skipped by this test. Confirmed clean today (73 real license paths, zero
        /// dangling) -- this closes a real, previously-unverified blind spot, not a currently-known
        /// defect.
        #[test]
        fn every_donor_license_path_that_is_a_file_reference_exists_on_disk() {
            let root = workspace_root();
            let entries = load_entries();
            let mut checked = 0usize;
            for entry in &entries {
                for path in &entry.license {
                    checked += 1;
                    assert!(
                        root.join(path).exists(),
                        "donor `{}`'s license path `{}` does not exist on disk -- a dangling \
                         license reference is exactly the kind of unverifiable legal/provenance \
                         claim this repository's own donor-absorption discipline forbids",
                        entry.id,
                        path
                    );
                }
            }
            assert!(
                checked > 0,
                "expected at least one donor to declare its license as a real file-path array \
                 (most donors do) -- zero checked means this test's own parsing has drifted"
            );
        }

        /// The reverse direction of the check above: every real, on-disk Technology Genome
        /// document must be cited by at least one donor's own `evidence` array, or it is an
        /// orphaned record no `donor-corpus.toml` entry actually points to -- invisible to anyone
        /// reading a donor's own evidence trail, even though the file itself exists. Confirmed
        /// clean today (this test was added, not because a defect was found, but because the
        /// blind spot it closes is real: nothing previously checked this direction at all), so
        /// this guards against a FUTURE genome document being written and never linked back, not
        /// a currently-known problem.
        #[test]
        fn every_genome_technology_document_is_referenced_by_some_donor() {
            let root = workspace_root();
            let genome_dir = root.join(".atlas/genome/technology");
            let entries = load_entries();
            let mut referenced: std::collections::HashSet<String> =
                std::collections::HashSet::new();
            for entry in &entries {
                for path in &entry.evidence {
                    if let Some(name) = path.strip_prefix(".atlas/genome/technology/") {
                        referenced.insert(name.to_owned());
                    }
                }
            }

            let mut genome_files: Vec<String> = std::fs::read_dir(&genome_dir)
                .expect(".atlas/genome/technology must exist and be readable")
                .filter_map(Result::ok)
                .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "md"))
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            genome_files.sort();
            assert!(
                !genome_files.is_empty(),
                "expected at least one Technology Genome document under .atlas/genome/technology \
                 -- this session alone wrote several; an empty directory means this test's own \
                 path resolution has drifted"
            );

            for file in &genome_files {
                assert!(
                    referenced.contains(file),
                    "`.atlas/genome/technology/{file}` exists on disk but is not cited in any \
                     donor's evidence array in donor-corpus.toml -- an orphaned genome record \
                     nobody's evidence trail points back to"
                );
            }
        }

        /// Every location a donor's source may be materialized at: the conventional
        /// `.atlas/temporary/donors/<id>`, plus its provenance record's own `clone_path` when that
        /// differs. Both are needed because 10 provenance records still carry the clone path from
        /// before their checkout was moved (e.g. `.atlas/temporary/wasmtime`, `.../ide/zed`) --
        /// recorded debt (`GENERATIONS.toml` deferred `stale-provenance-clone-paths`), not silently
        /// rewritten here.
        fn donor_clone_paths(root: &Path, id: &str) -> Vec<String> {
            let mut paths = vec![format!(".atlas/temporary/donors/{id}")];
            let provenance = root.join(format!(".atlas/provenance/donors/{id}.json"));
            let recorded = std::fs::read_to_string(provenance).ok().and_then(|text| {
                text.lines().find_map(|line| {
                    let rest = line.trim().strip_prefix("\"clone_path\": \"")?;
                    Some(rest[..rest.find('"')?].to_owned())
                })
            });
            if let Some(recorded) = recorded
                && !paths.contains(&recorded)
            {
                paths.push(recorded);
            }
            paths
        }

        /// Extinction is physical (`.atlas/roadmap/DONOR-ABSORPTION-PLAN.toml`:
        /// `extinct_requires_source_path_absent = true`): an `EXTINCT` claim with the checkout still
        /// on disk would be a status-field extinction, exactly what the donor lifecycle forbids. The
        /// converse holds too: a `CLONED` claim with no checkout anywhere is a stale record.
        #[test]
        fn every_extinct_donor_checkout_is_absent_and_every_cloned_one_present() {
            let root = workspace_root();
            let entries = load_entries();
            let mut extinct = 0;
            for entry in &entries {
                let paths = donor_clone_paths(&root, &entry.id);
                let present: Vec<&String> = paths
                    .iter()
                    .filter(|path| root.join(path).exists())
                    .collect();
                match entry.ingestion_status.as_str() {
                    "EXTINCT" => {
                        extinct += 1;
                        assert!(
                            present.is_empty(),
                            "donor `{}` is EXTINCT but its source still exists at {present:?}",
                            entry.id
                        );
                    }
                    "CLONED" => assert!(
                        !present.is_empty(),
                        "donor `{}` claims CLONED but none of {paths:?} exists",
                        entry.id
                    ),
                    // Censused remotely (ADR 0021): never materialized under an Atlas donor root.
                    "REMOTE_CENSUSED" => assert!(
                        present.is_empty(),
                        "donor `{}` is REMOTE_CENSUSED but source exists at {present:?}",
                        entry.id
                    ),
                    other => panic!(
                        "donor `{}` has unrecognized ingestion_status `{other}`",
                        entry.id
                    ),
                }
            }
            assert!(
                extinct >= 2,
                "expected at least souffle and datafrog to be EXTINCT"
            );
        }

        /// Every materialized donor checkout must belong to an admitted donor-corpus entry, or be a
        /// named, recorded blocker. The blockers live in `.atlas/roadmap/DONOR-WORKING-SET.toml`
        /// (`[[unadmitted_checkout]]`, ADR 0021) so the list has one source of truth and can only
        /// shrink: a new unadmitted checkout fails this test, and so does a listed one that has been
        /// admitted or deleted without updating the record.
        fn unadmitted_checkout_debt() -> Vec<String> {
            let text = std::fs::read_to_string(
                workspace_root().join(".atlas/roadmap/DONOR-WORKING-SET.toml"),
            )
            .expect("DONOR-WORKING-SET.toml");
            text.lines()
                .filter_map(|line| {
                    let rest = line.trim().strip_prefix("directory = \"")?;
                    Some(rest[..rest.find('"')?].to_owned())
                })
                .collect()
        }

        #[test]
        fn every_materialized_donor_checkout_is_admitted_or_recorded_debt() {
            let root = workspace_root();
            let debt = unadmitted_checkout_debt();
            let admitted_top_level: std::collections::BTreeSet<String> = load_entries()
                .iter()
                .filter(|entry| entry.ingestion_status == "CLONED")
                .flat_map(|entry| donor_clone_paths(&root, &entry.id))
                .filter(|path| root.join(path).is_dir())
                .filter_map(|path| {
                    path.strip_prefix(".atlas/temporary/donors/")
                        .and_then(|rest| rest.split('/').next())
                        .map(str::to_owned)
                })
                .collect();
            let mut on_disk: Vec<String> = std::fs::read_dir(root.join(".atlas/temporary/donors"))
                .expect(".atlas/temporary/donors must exist")
                .filter_map(Result::ok)
                .filter(|entry| entry.path().is_dir())
                .map(|entry| entry.file_name().to_string_lossy().into_owned())
                .collect();
            on_disk.sort();
            for dir in &on_disk {
                assert!(
                    admitted_top_level.contains(dir) || debt.contains(dir),
                    "`.atlas/temporary/donors/{dir}` is materialized donor source with no admitted \
                     donor-corpus entry and no recorded debt: admit it, or delete it"
                );
            }
            assert!(!debt.is_empty(), "no recorded blocker parsed");
            for debt in &debt {
                assert!(
                    on_disk.iter().any(|dir| dir == debt) && !admitted_top_level.contains(debt),
                    "`{debt}` is listed as unadmitted debt but was admitted or removed; update the list"
                );
            }
        }

        /// `.atlas/roadmap/GENERATIONS.toml` is the self-building loop's durable memory: the next
        /// generation reads it instead of any agent's recollection. A ledger that cites a missing
        /// evidence/decision path, or a base commit that is not a real 40-hex object name, would
        /// silently corrupt that memory, so both are enforced here (hand-parsed, matching this
        /// module's no-toml-crate discipline).
        #[test]
        fn generation_ledger_references_real_paths_and_real_base_commits() {
            let root = workspace_root();
            let text = std::fs::read_to_string(root.join(".atlas/roadmap/GENERATIONS.toml"))
                .expect("GENERATIONS.toml must exist and be readable");
            assert!(
                text.lines()
                    .any(|line| line.trim() == "schema = \"atlas.self-build.generation-ledger.v1\""),
                "ledger schema line missing"
            );
            let mut quoted = Vec::new();
            for line in text
                .lines()
                .filter(|line| !line.trim_start().starts_with('#'))
            {
                // ADR 0044/0067: a donor's `source_path` names what was deleted; it must be absent.
                if let Some(rest) = line.trim_start().strip_prefix("source_path = ") {
                    let path = rest.trim_matches('"');
                    // Unless a later replay recorded it MATERIALIZED again (FULL-OSS-REPLAY.toml).
                    let rematerialized =
                        std::fs::read_to_string(root.join(".atlas/roadmap/FULL-OSS-REPLAY.toml"))
                            .unwrap_or_default()
                            .split("\n[[repository]]\n")
                            .any(|r| {
                                r.contains(&format!("source_path = \"{path}\""))
                                    && r.contains("replay_status = \"MATERIALIZED\"")
                            });
                    assert!(
                        !root.join(path).exists() || rematerialized,
                        "donor source `{path}` still exists"
                    );
                    continue;
                }
                extract_quoted_strings(line, &mut quoted);
            }
            let paths: Vec<&String> = quoted.iter().filter(|q| q.starts_with(".atlas/")).collect();
            assert!(!paths.is_empty(), "ledger cites no evidence at all");
            for path in paths {
                assert!(
                    root.join(path).exists(),
                    "GENERATIONS.toml cites `{path}`, which does not exist"
                );
            }
            // Every recorded commit must be a full object name AND a real commit: a plausible-looking
            // but invented hash is exactly the failure a memory-free loop cannot detect by rereading
            // its own ledger (it happened once while this ledger was being written). Existence is
            // skipped only when the checkout has no history beyond HEAD at all (CI's depth-1 clone).
            // Merely being shallow is not enough to skip: this loop itself runs in a shallow clone,
            // and ledger commits are always recent enough to resolve in one.
            let has_history = std::process::Command::new("git")
                .args(["-C", &root.to_string_lossy(), "rev-parse", "--verify", "-q"])
                .arg("HEAD~1^{commit}")
                .status()
                .is_ok_and(|status| status.success());
            let mut generations = 0;
            let mut shas = Vec::new();
            for line in text.lines() {
                let trimmed = line.trim();
                if let Some(rest) = trimmed.strip_prefix("base_commit = \"") {
                    generations += 1;
                    shas.push(rest.trim_end_matches('"').to_owned());
                } else if trimmed.starts_with("result_commits = [") {
                    extract_quoted_strings(trimmed, &mut shas);
                }
            }
            for sha in &shas {
                assert!(
                    sha.len() == 40 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
                    "ledger commit `{sha}` is not a full object name"
                );
                if has_history {
                    let exists = std::process::Command::new("git")
                        .args(["-C", &root.to_string_lossy(), "cat-file", "-e"])
                        .arg(format!("{sha}^{{commit}}"))
                        .status()
                        .is_ok_and(|status| status.success());
                    assert!(
                        exists,
                        "ledger commit `{sha}` is not a real commit in this repository"
                    );
                }
            }
            assert!(generations > 0, "ledger records no generation");
        }

        /// `.atlas/roadmap/FIRST-50-CAMPAIGN.toml` (P3) is the canonical donor execution order:
        /// ordinals 1..=50 exactly once, every admitted donor either queued or excluded with a
        /// reason (never silently dropped), every entry in the repo-exact frontier, historical
        /// proofs consistent with the donor corpus, and a dashboard recomputable from the entries.
        #[test]
        fn first_50_campaign_is_canonical_and_accounted() {
            let root = workspace_root();
            let text = std::fs::read_to_string(root.join(".atlas/roadmap/FIRST-50-CAMPAIGN.toml"))
                .expect("FIRST-50-CAMPAIGN.toml");
            let field = |block: &str, name: &str| {
                block.lines().find_map(|line| {
                    let rest = line.trim().strip_prefix(name)?.strip_prefix(" = ")?;
                    Some(rest.trim().trim_matches('"').to_owned())
                })
            };
            let frontier =
                std::fs::read_to_string(root.join(".atlas/roadmap/RECOMMENDED-OSS-FRONTIER.toml"))
                    .expect("frontier")
                    .to_ascii_lowercase();
            let corpus: std::collections::BTreeMap<String, (String, String)> = load_entries()
                .into_iter()
                .map(|e| {
                    (
                        e.id.clone(),
                        (e.ingestion_status.clone(), e.decision_status.clone()),
                    )
                })
                .collect();
            let mut ordinals = Vec::new();
            let mut queued = std::collections::BTreeSet::new();
            let (mut absorbed, mut terminal_historic, mut remaining) = (0, 0, 0);
            let (mut terminal_campaign, mut reference_only, mut extinct, mut deep) = (0, 0, 0, 0);
            let ledger = std::fs::read_to_string(root.join(".atlas/roadmap/GENERATIONS.toml"))
                .expect("GENERATIONS.toml");
            let mut first_pending = None;
            for block in text.split("[[donor]]").skip(1) {
                let block = block.split("[[outside_first_50]]").next().unwrap();
                let ordinal: usize = field(block, "ordinal").unwrap().parse().unwrap();
                let repository = field(block, "repository").unwrap();
                let url = field(block, "canonical_url").unwrap();
                let status = field(block, "current_status").unwrap();
                let lifecycle = field(block, "lifecycle").unwrap();
                let terminal = field(block, "terminal_state").unwrap();
                ordinals.push(ordinal);
                assert!(
                    queued.insert(repository.clone()),
                    "{repository} queued twice"
                );
                assert!(
                    frontier.contains(&format!("canonical_url = \"{}\"", url.to_ascii_lowercase())),
                    "{repository}: {url} not in the repo-exact frontier"
                );
                assert!(
                    [
                        "HISTORICALLY_PROVEN",
                        "CURRENTLY_PENDING",
                        "CAMPAIGN_PROVEN"
                    ]
                    .contains(&status.as_str()),
                    "{repository}: {status}"
                );
                // A donor completed inside the campaign names its generation and evidence, is
                // terminal, and its corpus record agrees (a deleted source is EXTINCT).
                if status == "CAMPAIGN_PROVEN" {
                    terminal_campaign += 1;
                    assert_eq!(
                        lifecycle, "TERMINAL",
                        "{repository}: CAMPAIGN_PROVEN not terminal"
                    );
                    let generation = field(block, "completed_in")
                        .unwrap_or_else(|| panic!("{repository}: no completed_in"));
                    assert!(
                        ledger.contains(&format!("id = \"{generation}\"")),
                        "{repository}: completed_in {generation} is not in the ledger"
                    );
                    let evidence = field(block, "evidence")
                        .unwrap_or_else(|| panic!("{repository}: no evidence"));
                    assert!(
                        root.join(&evidence).is_file(),
                        "{repository}: {evidence} missing"
                    );
                    match corpus.get(&repository) {
                        Some((ingestion, decision)) => {
                            assert_eq!(ingestion, "EXTINCT", "{repository}: source not extinct");
                            assert_eq!(
                                decision, &terminal,
                                "{repository}: corpus decision differs"
                            );
                        }
                        // Decided without admission (G108): a donor settled at the consumer gate,
                        // or whose mechanism was absorbed from its published specification alone
                        // (G109), has no corpus record and no source to extinguish -- allowed only
                        // while the frontier still records it as never admitted.
                        None => {
                            let url = url.to_ascii_lowercase();
                            let record = frontier
                                .split("[[repository]]")
                                .find(|r| r.contains(&format!("canonical_url = \"{url}\"")))
                                .unwrap();
                            assert!(
                                record.contains("lifecycle = \"candidate\"")
                                    && record.contains("working_set = \"consumer_gated\""),
                                "{repository}: campaign proof outside the corpus for an admitted \
                                 repository"
                            );
                        }
                    }
                }
                if terminal == "REFERENCE_ONLY" {
                    reference_only += 1;
                }
                if lifecycle == "DEEP_CENSUSED" {
                    deep += 1;
                }
                if corpus
                    .get(&repository)
                    .is_some_and(|(ingestion, _)| ingestion == "EXTINCT")
                {
                    extinct += 1;
                }
                if lifecycle == "TERMINAL" {
                    assert!(
                        !terminal.is_empty(),
                        "{repository}: TERMINAL without a terminal state"
                    );
                } else {
                    remaining += 1;
                    if status == "CURRENTLY_PENDING" && first_pending.is_none() {
                        first_pending = Some(repository.clone());
                    }
                }
                if terminal == "ABSORBED" {
                    absorbed += 1;
                }
                if status == "HISTORICALLY_PROVEN" {
                    let (ingestion, _) = corpus.get(&repository).unwrap_or_else(|| {
                        panic!("{repository}: historical proof outside the corpus")
                    });
                    if lifecycle == "TERMINAL" {
                        terminal_historic += 1;
                        assert_eq!(
                            ingestion, "EXTINCT",
                            "{repository}: terminal history must be extinct"
                        );
                    }
                }
            }
            assert_eq!(
                ordinals,
                (1..=50).collect::<Vec<_>>(),
                "ordinals must be 1..=50 in order"
            );
            let mut outside = std::collections::BTreeSet::new();
            for block in text.split("[[outside_first_50]]").skip(1) {
                let repository = field(block, "repository").unwrap();
                assert!(
                    !field(block, "reason").unwrap_or_default().is_empty(),
                    "{repository}: no reason"
                );
                assert!(outside.insert(repository.clone()));
                assert!(
                    !queued.contains(&repository),
                    "{repository} both queued and excluded"
                );
            }
            for id in corpus.keys() {
                assert!(
                    queued.contains(id) || outside.contains(id),
                    "admitted donor `{id}` is neither in the first-50 nor excluded with a reason"
                );
            }
            let dashboard = text
                .split("[dashboard]")
                .nth(1)
                .unwrap()
                .split("[[donor]]")
                .next()
                .unwrap();
            let count = |k: &str| -> usize { field(dashboard, k).unwrap().parse().unwrap() };
            assert_eq!(count("first_50_total"), 50);
            assert_eq!(count("absorbed"), absorbed);
            assert_eq!(count("historic_terminal"), terminal_historic);
            assert_eq!(count("campaign_terminal"), terminal_campaign);
            assert_eq!(count("reference_only"), reference_only);
            assert_eq!(count("extinct"), extinct);
            assert_eq!(count("deep_censused"), deep);
            assert_eq!(count("remaining"), remaining);
            assert_eq!(field(dashboard, "next_donor"), first_pending);
        }

        /// ADR 0024: from G57, NEXTGEN is proven by self-recensus. Every generation records its
        /// priority (P0-P6, or a P7 workload naming the P0-P6 proof it serves) and a PROVEN
        /// self-recensus report whose before/after digests match its recorded pre/post snapshots;
        /// and each generation's pre-change census equals the previous generation's post-change
        /// census, so the chain of Atlases is auditable end to end.
        #[test]
        fn generation_ledger_self_recensus_chain() {
            let _census = crate::whole_repo_census_lock();
            use crate::recensus::{SelfRecensusReport, Verdict, read_snapshot};
            let root = workspace_root();
            let text = std::fs::read_to_string(root.join(".atlas/roadmap/GENERATIONS.toml"))
                .expect("GENERATIONS.toml");
            let field = |block: &str, name: &str| {
                block.lines().find_map(|line| {
                    let rest = line.trim().strip_prefix(name)?.strip_prefix(" = \"")?;
                    Some(rest[..rest.find('"')?].to_owned())
                })
            };
            let mut previous_post: Option<(String, String)> = None;
            let mut without_committed_census = Vec::new();
            let mut proven = 0;
            for block in text.split("\n[[generation]]").skip(1) {
                let id = field(block, "id").expect("generation id");
                let number: u32 = id.trim_start_matches('G').parse().unwrap_or(0);
                if number < 57 {
                    continue;
                }
                let priority = field(block, "priority")
                    .unwrap_or_else(|| panic!("{id}: no priority (PRIORITY.toml)"));
                let serves = field(block, "serves").unwrap_or_default();
                assert!(
                    ["P0", "P1", "P2", "P3", "P4", "P5", "P6"].contains(&priority.as_str())
                        || (priority == "P7"
                            && ["P0", "P1", "P2", "P3", "P4", "P5", "P6"]
                                .iter()
                                .any(|p| serves.contains(p))),
                    "{id}: priority `{priority}` must be P0-P6, or P7 serving a P0-P6 proof"
                );
                assert!(
                    !serves.trim().is_empty(),
                    "{id}: `serves` must state the proof it serves"
                );
                let report_path = field(block, "self_recensus").unwrap_or_else(|| {
                    panic!("{id}: no self_recensus report: GENERATION_NOT_PROVEN")
                });
                let dir = std::path::Path::new(&report_path)
                    .parent()
                    .expect("report directory")
                    .to_path_buf();
                let report: SelfRecensusReport = serde_json::from_str(
                    &std::fs::read_to_string(root.join(&report_path))
                        .unwrap_or_else(|e| panic!("{id}: {report_path}: {e}")),
                )
                .unwrap_or_else(|e| panic!("{id}: {report_path}: {e}"));
                assert_eq!(report.generation, id);
                assert_eq!(
                    report.verdict,
                    Verdict::Proven,
                    "{id}: {:?}",
                    report.regressions
                );
                let pre = read_snapshot(root.join(dir.join("pre.json")))
                    .unwrap_or_else(|e| panic!("{id}: pre snapshot: {e}"));
                let post = read_snapshot(root.join(dir.join("post.json")))
                    .unwrap_or_else(|e| panic!("{id}: post snapshot: {e}"));
                assert_eq!(
                    pre.census_digest, report.before_census_digest,
                    "{id}: pre digest"
                );
                assert_eq!(
                    post.census_digest, report.after_census_digest,
                    "{id}: post digest"
                );
                assert_eq!(
                    report.after_census_digest, report.replay_digest,
                    "{id}: replay"
                );
                if let Some((previous_id, previous_digest)) = &previous_post {
                    assert_eq!(
                        &pre.census_digest, previous_digest,
                        "{id}: pre-change census must equal {previous_id}'s post-change census"
                    );
                }
                // in-toto's MATCH rule on products (G109): the post-change census a generation
                // proves must be the census of the tree it committed, which the clean-HEAD
                // `atlas pack` evidence (`atlas.json`) records -- an inspection re-deriving the
                // step's product. The newest generation's evidence lands in the commit after it.
                let committed = root.join(dir.join("atlas.json"));
                if committed.is_file() {
                    let atlas: serde_json::Value =
                        serde_json::from_str(&std::fs::read_to_string(&committed).unwrap())
                            .unwrap_or_else(|e| panic!("{id}: atlas.json: {e}"));
                    assert_eq!(
                        atlas["census_digest"].as_str(),
                        Some(post.census_digest.as_str()),
                        "{id}: the committed tree's census differs from the proven post-change census"
                    );
                } else {
                    without_committed_census.push(id.clone());
                }
                previous_post = Some((id.clone(), post.census_digest.clone()));
                proven += 1;
            }
            assert!(proven >= 1, "no self-recensus-proven generation recorded");
            // Generations before `atlas pack` existed (G57-G63) and G65 recorded no clean-HEAD
            // container; any other gap is a missing inspection.
            let newest = previous_post.map(|(id, _)| id).unwrap_or_default();
            let before_pack = ["G57", "G58", "G59", "G60", "G61", "G62", "G63", "G65"];
            for id in &without_committed_census {
                assert!(
                    *id == newest || before_pack.contains(&id.as_str()),
                    "{id}: no clean-HEAD atlas.json evidence of the committed census"
                );
            }
        }

        /// `.atlas/roadmap/RECOMMENDED-OSS-FRONTIER.toml` (G53) is the repo-exact OSS frontier:
        /// one `[[repository]]` per canonical remote URL, so a monorepo subtree (MLIR), an
        /// ecosystem (ROS 2) or an alias can never be silently counted as a repository. Every
        /// head must be a full object name read from the live remote, every donor-corpus record
        /// must resolve to exactly the repository that carries its id with a matching lifecycle,
        /// and every recorded count must equal the count recomputed from the entries.
        #[test]
        fn recommended_frontier_is_repo_exact_and_counted() {
            use std::collections::{BTreeMap, BTreeSet};
            let root = workspace_root();
            let text =
                std::fs::read_to_string(root.join(".atlas/roadmap/RECOMMENDED-OSS-FRONTIER.toml"))
                    .expect("RECOMMENDED-OSS-FRONTIER.toml must exist and be readable");
            let mut tables: Vec<(String, BTreeMap<String, String>)> =
                vec![(String::new(), BTreeMap::new())];
            for line in text.lines().map(str::trim) {
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if line.starts_with('[') {
                    tables.push((line.to_owned(), BTreeMap::new()));
                } else if let Some((key, value)) = line.split_once(" = ") {
                    let table = &mut tables.last_mut().expect("root table").1;
                    table.insert(key.to_owned(), value.to_owned());
                }
            }
            let quoted = |value: &str| {
                let mut out = Vec::new();
                extract_quoted_strings(value, &mut out);
                out
            };
            let single = |table: &BTreeMap<String, String>, key: &str| {
                quoted(table.get(key).map_or("", String::as_str))
                    .into_iter()
                    .next()
                    .unwrap_or_default()
            };
            let of = |header: &str| -> Vec<&BTreeMap<String, String>> {
                tables
                    .iter()
                    .filter(|(h, _)| h == header)
                    .map(|(_, t)| t)
                    .collect()
            };
            let counts = of("[exact_counts]")
                .first()
                .copied()
                .expect("[exact_counts] missing");
            let count = |key: &str| -> usize {
                counts
                    .get(key)
                    .unwrap_or_else(|| panic!("exact_counts.{key} missing"))
                    .parse()
                    .unwrap_or_else(|_| panic!("exact_counts.{key} is not a count"))
            };
            let key = |url: &str| url.to_ascii_lowercase().trim_end_matches(".git").to_owned();

            let repositories = of("[[repository]]");
            let mut urls = BTreeSet::new();
            let mut lifecycles: BTreeMap<String, usize> = BTreeMap::new();
            let mut working_sets: BTreeMap<String, usize> = BTreeMap::new();
            let mut by_corpus_id: BTreeMap<String, (String, String)> = BTreeMap::new();
            let (mut directive, mut corpus, mut lane_only) = (0, 0, 0);
            for repository in &repositories {
                let url = single(repository, "canonical_url");
                assert!(
                    url.starts_with("https://") && url.len() > "https://".len(),
                    "`{url}` is not a canonical https remote"
                );
                assert!(urls.insert(key(&url)), "`{url}` is listed twice");
                let head = single(repository, "verified_head");
                assert!(
                    head.len() == 40 && head.bytes().all(|b| b.is_ascii_hexdigit()),
                    "`{url}` has no full verified_head"
                );
                assert!(
                    !quoted(&repository["names"]).is_empty(),
                    "`{url}` records no name"
                );
                assert!(
                    !single(repository, "license").is_empty(),
                    "`{url}` records no license"
                );
                let lifecycle = single(repository, "lifecycle");
                let working_set = single(repository, "working_set");
                let expected_working_set = match lifecycle.as_str() {
                    "ADMITTED" => "MATERIALIZED",
                    "ADMITTED_REMOTE" => "REMOTE_ONLY",
                    "EXTINCT" => "EXTINCT",
                    "CANDIDATE" | "CANDIDATE_OVERLAPPING" => "CONSUMER_GATED",
                    "EXTERNAL_ORACLE" => "ORACLE_ONLY",
                    "EXTERNAL_PROVIDER_ARTIFACT" | "REJECTED_UNLICENSED" => "EXCLUDED",
                    other => panic!("`{url}` has unknown lifecycle `{other}`"),
                };
                assert_eq!(working_set, expected_working_set, "`{url}` working_set");
                let origins = quoted(&repository["origins"]);
                assert!(!origins.is_empty(), "`{url}` records no origin");
                directive += usize::from(origins.iter().any(|o| o == "DIRECTIVE"));
                corpus += usize::from(origins.iter().any(|o| o == "CORPUS"));
                lane_only += usize::from(origins == ["LANE"]);
                let ids = quoted(&repository["corpus_ids"]);
                assert_eq!(
                    ids.is_empty(),
                    !origins.iter().any(|o| o == "CORPUS"),
                    "`{url}`: corpus_ids and the CORPUS origin must agree"
                );
                for id in ids {
                    by_corpus_id.insert(id, (key(&url), lifecycle.clone()));
                }
                *lifecycles.entry(lifecycle).or_default() += 1;
                *working_sets.entry(working_set).or_default() += 1;
            }

            // Every donor-corpus record resolves to the repository carrying its id.
            let corpus_text =
                std::fs::read_to_string(root.join(".atlas/references/donor-corpus.toml"))
                    .expect("donor-corpus.toml");
            let mut donors = Vec::new();
            for block in corpus_text.split("[[donor]]").skip(1) {
                let field = |name: &str| {
                    block.lines().find_map(|line| {
                        let rest = line.trim().strip_prefix(name)?.strip_prefix(" = \"")?;
                        Some(rest[..rest.find('"')?].to_owned())
                    })
                };
                donors.push((
                    field("id").expect("donor id"),
                    field("resolved_url").expect("donor resolved_url"),
                    field("ingestion_status").expect("donor ingestion_status"),
                ));
            }
            assert!(!donors.is_empty(), "no donor parsed");
            // A repository several corpus donors slice (mlir and llvm-project) is extinct only
            // once every slice is; until then it carries the lifecycle of its live slices.
            let mut slices: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();
            for (id, url, ingestion) in &donors {
                let (repository, _) = by_corpus_id
                    .get(id)
                    .unwrap_or_else(|| panic!("corpus donor `{id}` has no frontier repository"));
                assert_eq!(
                    repository,
                    &key(url),
                    "corpus donor `{id}` resolves elsewhere"
                );
                let expected = match ingestion.as_str() {
                    "EXTINCT" => "EXTINCT",
                    "REMOTE_CENSUSED" => "ADMITTED_REMOTE",
                    _ => "ADMITTED",
                };
                slices
                    .entry(repository.clone())
                    .or_default()
                    .insert(expected);
            }
            for (id, _, _) in &donors {
                let (repository, lifecycle) = &by_corpus_id[id];
                let live: Vec<&str> = slices[repository]
                    .iter()
                    .copied()
                    .filter(|expected| *expected != "EXTINCT")
                    .collect();
                let expected = match live.as_slice() {
                    [] => "EXTINCT",
                    [one] => one,
                    _ => panic!("`{repository}`: its live slices disagree: {live:?}"),
                };
                assert_eq!(lifecycle, expected, "corpus donor `{id}` lifecycle");
            }
            assert_eq!(
                by_corpus_id.len(),
                donors.len(),
                "a frontier corpus_id names no corpus donor"
            );

            // Ecosystems and subtrees are names over repositories, never repositories themselves.
            let ecosystems = of("[[ecosystem]]");
            for ecosystem in &ecosystems {
                let members = quoted(&ecosystem["members"]);
                assert!(!members.is_empty(), "an ecosystem has no member");
                for member in members {
                    assert!(
                        urls.contains(&key(&member)),
                        "ecosystem member `{member}` unlisted"
                    );
                }
            }
            let subtrees = of("[[subtree_alias]]");
            for subtree in &subtrees {
                let parent = single(subtree, "parent");
                assert!(
                    urls.contains(&key(&parent)),
                    "subtree parent `{parent}` unlisted"
                );
            }

            assert_eq!(count("canonical_repositories"), repositories.len());
            assert_eq!(count("directive_named_repositories"), directive);
            assert_eq!(count("corpus_repositories"), corpus);
            assert_eq!(count("lane_only_repositories"), lane_only);
            assert_eq!(count("ecosystems"), ecosystems.len());
            assert_eq!(count("subtree_aliases"), subtrees.len());
            assert_eq!(
                count("non_repository_names"),
                of("[[non_repository_name]]").len()
            );
            for (lifecycle, n) in &lifecycles {
                assert_eq!(
                    count(&format!("lifecycle_{}", lifecycle.to_ascii_lowercase())),
                    *n
                );
            }
            for (working_set, n) in &working_sets {
                assert_eq!(
                    count(&format!("working_set_{}", working_set.to_ascii_lowercase())),
                    *n
                );
            }
            let recorded: usize = counts
                .iter()
                .filter(|(k, _)| k.starts_with("lifecycle_"))
                .map(|(_, v)| v.parse::<usize>().unwrap())
                .sum();
            assert_eq!(
                recorded,
                repositories.len(),
                "a lifecycle count has no entries"
            );
            let reconciliation = of("[reconciliation]")
                .first()
                .copied()
                .expect("[reconciliation]");
            assert_eq!(
                reconciliation["repo_exact_total"].parse::<usize>().ok(),
                Some(repositories.len())
            );
        }

        /// A `decision_status` of bare `"PENDING"` is only an honest claim when the donor's own
        /// `census_status` says census depth genuinely never reached the point a decision could be
        /// made (`SKELETON`, or `PENDING_DEEP_CENSUS`). This session found 8 donors that violated
        /// that: their `census_status` already showed a completed (or lane-level-concluded) census
        /// -- each with a real, dated, per-mechanism disposition already recorded in its own
        /// census document (and, for the semantic-graph-language-lane donors, in a shared lane
        /// synthesis document's own `## Decision` section) -- yet `decision_status` still read the
        /// literal placeholder `"PENDING"`, silently misrepresenting an already-resolved judgment
        /// as still-open. One donor's own census doc (`duumbi.md`) explicitly names the missing
        /// step: "A coordinator must merge applicable Discoveries/target_owners into ...
        /// donor-corpus.toml separately" -- that merge was never done. This formalizes the
        /// invariant those 8 corrections restored, so a future census-complete donor can never
        /// again go unsynced silently.
        #[test]
        fn pending_decision_status_only_appears_on_a_genuinely_uncensused_donor() {
            const HONEST_PENDING_CENSUS_STATUSES: &[&str] = &["SKELETON", "PENDING_DEEP_CENSUS"];
            let entries = load_entries();
            let mut violations = Vec::new();
            for entry in &entries {
                if entry.decision_status == "PENDING"
                    && !HONEST_PENDING_CENSUS_STATUSES.contains(&entry.census_status.as_str())
                {
                    violations.push(format!(
                        "donor `{}` has decision_status = \"PENDING\" but census_status = \"{}\" \
                         -- census depth beyond {:?} means a real decision should already be \
                         recorded (in the donor's own census doc or a lane synthesis doc) and \
                         mirrored into decision_status, not left as an unsynced placeholder",
                        entry.id, entry.census_status, HONEST_PENDING_CENSUS_STATUSES
                    ));
                }
            }
            assert!(
                violations.is_empty(),
                "found donor-corpus.toml entries with a stale, unsynced PENDING decision_status:\n\n{}",
                violations.join("\n")
            );
        }
    }

    /// ADR 0038 (G116) and ADR 0040 (G118 hard stop): essential complexity is debt, not a donor
    /// verdict. These tests make the anti-avoidance discipline a CI property: the age, escalation
    /// and skip-budget alarms are recomputed from the ledger head and the donor audit; an alarmed
    /// debt must be planned; a debt closes only with native or boundary evidence; every donor
    /// carries separate mechanism and capability decisions; and while
    /// `.atlas/roadmap/FOUNDATIONAL-ATLAS-READY.toml` blocks donor progression and frontier
    /// expansion, any donor or frontier progress fails the build.
    mod essential_complexity {
        use std::collections::{BTreeMap, BTreeSet};
        use std::path::{Path, PathBuf};

        const MATURITY: [&str; 6] = [
            "M0_ABSENT",
            "M1_CONTRACT_ONLY",
            "M2_PARTIAL",
            "M3_SINGLE_ENGINE_BOUNDED",
            "M4_MULTI_ENGINE_RECONCILED",
            "M5_CLOSED_WITH_ORACLE",
        ];
        const LEDGER: &str = ".atlas/roadmap/ESSENTIAL-COMPLEXITY-DEBT.toml";
        const AUDIT: &str = ".atlas/roadmap/DONOR-CAPABILITY-AUDIT.toml";
        const GATE: &str = ".atlas/roadmap/FOUNDATIONAL-ATLAS-READY.toml";
        const PRESSURE: &str = ".atlas/roadmap/ARCHITECTURE-PRESSURE-MAP.toml";
        const REVALIDATION: &str = ".atlas/roadmap/RECURSIVE-DONOR-REVALIDATION.toml";
        const TERMINAL: [&str; 5] = [
            "ABSORBED",
            "REFERENCE_ONLY",
            "REFERENCE_ONLY_UNTIL_TRIGGER",
            "EXTERNAL_BOUNDARY",
            "REJECTED",
        ];
        const BOUNDARY_TYPES: [&str; 4] = [
            "PERMANENT_REALITY",
            "BOOTSTRAP",
            "ORACLE",
            "TEMPORARY_UNTIL_NATIVE",
        ];
        const VAGUE: [&str; 6] = [
            "later",
            "when needed",
            "tbd",
            "todo",
            "someday",
            "eventually",
        ];

        fn root() -> PathBuf {
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .canonicalize()
                .expect("workspace root must exist")
        }

        fn read(path: &str) -> String {
            std::fs::read_to_string(root().join(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
        }

        /// The bodies of every `[[table]]` array element, each cut at the next table header.
        fn blocks<'a>(text: &'a str, table: &str) -> Vec<&'a str> {
            text.split(&format!("\n[[{table}]]\n"))
                .skip(1)
                .map(|block| block.split("\n[").next().unwrap_or(block))
                .collect()
        }

        /// The body of a `[table]`, cut at the next table header.
        fn table<'a>(text: &'a str, name: &str) -> &'a str {
            let body = text
                .split(&format!("\n[{name}]\n"))
                .nth(1)
                .unwrap_or_else(|| panic!("missing [{name}]"));
            body.split("\n[").next().unwrap_or(body)
        }

        fn raw<'a>(block: &'a str, name: &str) -> Option<&'a str> {
            block
                .lines()
                .find_map(|line| line.trim().strip_prefix(name)?.strip_prefix(" = "))
        }

        fn string(block: &str, name: &str) -> Option<String> {
            let rest = raw(block, name)?.strip_prefix('"')?;
            Some(rest[..rest.find('"')?].to_owned())
        }

        fn text(block: &str, name: &str) -> String {
            let value = string(block, name).unwrap_or_default();
            assert!(!value.trim().is_empty(), "missing `{name}` in:\n{block}");
            value
        }

        fn number(block: &str, name: &str) -> i64 {
            raw(block, name)
                .and_then(|v| v.trim().parse().ok())
                .unwrap_or_else(|| panic!("missing integer `{name}` in:\n{block}"))
        }

        fn flag(block: &str, name: &str) -> bool {
            match raw(block, name).map(str::trim) {
                Some("true") => true,
                Some("false") => false,
                other => panic!("`{name}` must be a boolean, got {other:?} in:\n{block}"),
            }
        }

        fn list(block: &str, name: &str) -> Vec<String> {
            let value = raw(block, name)
                .unwrap_or_else(|| panic!("missing list `{name}` in:\n{block}"))
                .trim();
            assert!(
                value.starts_with('[') && value.ends_with(']'),
                "`{name}` must be a single-line list"
            );
            value
                .split('"')
                .skip(1)
                .step_by(2)
                .map(str::to_owned)
                .collect()
        }

        /// `G116` -> 116; `pre-G57` (decided before the ledger floor) -> 0.
        fn generation(id: &str) -> i64 {
            if id.starts_with("pre") {
                return 0;
            }
            id.trim_start_matches('G')
                .parse()
                .unwrap_or_else(|_| panic!("not a generation id: {id}"))
        }

        fn is_vague(value: &str) -> bool {
            let lower = value.to_ascii_lowercase();
            let words: Vec<&str> = lower.split(|c: char| !c.is_ascii_alphanumeric()).collect();
            VAGUE.iter().any(|v| {
                if v.contains(' ') {
                    lower.contains(v)
                } else {
                    words.contains(v)
                }
            })
        }

        /// The ledger's `[[generation]]` blocks with their ids.
        fn ledger_generations() -> Vec<(String, String)> {
            read(".atlas/roadmap/GENERATIONS.toml")
                .split("\n[[generation]]\n")
                .skip(1)
                .map(|block| {
                    (
                        string(block, "id").expect("generation id"),
                        block.to_owned(),
                    )
                })
                .collect()
        }

        /// The ledger head, which the GENERATIONS.toml header's `current_generation` must name.
        fn current_generation() -> i64 {
            let ledger = read(".atlas/roadmap/GENERATIONS.toml");
            let last = ledger_generations().last().expect("generations").0.clone();
            let header = ledger.split("\n[[").next().unwrap();
            assert_eq!(
                string(header, "current_generation").as_deref(),
                Some(last.as_str()),
                "GENERATIONS.toml current_generation must name the ledger head"
            );
            generation(&last)
        }

        struct Ledger {
            text: String,
            header: String,
        }

        impl Ledger {
            fn load() -> Self {
                let text = read(LEDGER);
                let header = text.split("\n[[").next().unwrap().to_owned();
                Ledger { text, header }
            }
            fn debts(&self) -> BTreeMap<String, &str> {
                let mut debts = BTreeMap::new();
                for block in blocks(&self.text, "debt") {
                    let id = text(block, "id");
                    assert!(debts.insert(id.clone(), block).is_none(), "{id} twice");
                }
                debts
            }
            fn scale_ids(&self) -> BTreeSet<String> {
                blocks(&self.text, "scale_trigger")
                    .into_iter()
                    .map(|block| text(block, "id"))
                    .collect()
            }
            /// Every id a companion file may cite: essential debts and scale triggers.
            fn known_ids(&self) -> BTreeSet<String> {
                let mut ids: BTreeSet<String> = self.debts().into_keys().collect();
                ids.extend(self.scale_ids());
                ids
            }
            /// Debt id -> the first queue position whose attack names it.
            fn queued(&self) -> BTreeMap<String, i64> {
                let mut queued = BTreeMap::new();
                for block in blocks(&self.text, "native_attack") {
                    let position = number(block, "position");
                    for debt in list(block, "debts") {
                        queued.entry(debt).or_insert(position);
                    }
                }
                queued
            }
            fn attack_ids(&self) -> BTreeSet<String> {
                let mut ids: BTreeSet<String> = blocks(&self.text, "native_attack")
                    .into_iter()
                    .map(|b| text(b, "id"))
                    .collect();
                ids.extend(
                    blocks(&self.text, "native_attack_done")
                        .into_iter()
                        .map(|b| text(b, "id")),
                );
                ids
            }
        }

        struct Donor {
            name: String,
            block: String,
        }

        fn donors() -> Vec<Donor> {
            let audit = read(AUDIT);
            blocks(&audit, "donor")
                .into_iter()
                .map(|block| Donor {
                    name: text(block, "donor"),
                    block: block.to_owned(),
                })
                .collect()
        }

        /// Trailing run of non-advancing First-50 donor decisions on `debt` made after its last
        /// advance, in decision order (the skip budget's input). Only decided (terminal)
        /// decisions count; a DEFERRED record behind the hard stop is not a decision.
        fn non_advancing_streak(debt: &str, last_advance: i64) -> i64 {
            let mut decisions: Vec<(i64, i64, bool)> = donors()
                .iter()
                .filter(|d| {
                    list(&d.block, "debts").iter().any(|x| x == debt)
                        && TERMINAL.contains(&text(&d.block, "mechanism_decision").as_str())
                        && number(&d.block, "first_50_ordinal") > 0
                })
                .map(|d| {
                    (
                        generation(&text(&d.block, "decided_in")),
                        number(&d.block, "first_50_ordinal"),
                        flag(&d.block, "advanced"),
                    )
                })
                .collect();
            decisions.sort();
            let mut streak = 0;
            for (decided, _, advanced) in decisions {
                if decided <= last_advance {
                    continue;
                }
                streak = if advanced { 0 } else { streak + 1 };
            }
            streak
        }

        /// Source paths of revalidations still IN_PROGRESS (their transient checkout may exist).
        fn in_progress_revalidation_paths() -> Vec<String> {
            let revalidation = read(REVALIDATION);
            blocks(&revalidation, "revalidation")
                .into_iter()
                .filter(|r| text(r, "status") == "IN_PROGRESS")
                .map(|r| text(r, "source_path"))
                .collect()
        }

        fn escalation(stale: i64, header: &str) -> &'static str {
            if stale >= number(header, "block_donor_progress_at") {
                "BLOCK_NEW_DONOR_PROGRESS"
            } else if stale >= number(header, "escalate_at") {
                "PRIORITY_ESCALATION"
            } else if stale >= number(header, "review_at") {
                "REVIEW_REQUIRED"
            } else {
                "TRACK"
            }
        }

        /// The debts that block donor progression now: OPEN and at BLOCK_NEW_DONOR_PROGRESS, or
        /// past the skip budget -- recomputed, never read from the gate file.
        fn progression_blockers() -> Vec<String> {
            let ledger = Ledger::load();
            let current = current_generation();
            let budget = number(&ledger.header, "skip_budget");
            ledger
                .debts()
                .into_iter()
                .filter(|(id, block)| {
                    let last = generation(&text(block, "last_advance_generation"));
                    text(block, "current_state") == "OPEN"
                        && (escalation(current - last, &ledger.header)
                            == "BLOCK_NEW_DONOR_PROGRESS"
                            || non_advancing_streak(id, last) >= budget)
                })
                .map(|(id, _)| id)
                .collect()
        }

        fn donor_progression_blocked() -> bool {
            let gate = read(GATE);
            text(table(&gate, "audit"), "status") != "COMPLETE"
                || !progression_blockers().is_empty()
        }

        #[test]
        fn debt_ledger_is_complete_and_its_alarms_are_planned() {
            let ledger = Ledger::load();
            let debts = ledger.debts();
            let queued = ledger.queued();
            let current = current_generation();
            let as_of = generation(&text(&ledger.header, "ages_as_of"));
            let (review, escalate, block, budget) = (
                number(&ledger.header, "review_at"),
                number(&ledger.header, "escalate_at"),
                number(&ledger.header, "block_donor_progress_at"),
                number(&ledger.header, "skip_budget"),
            );
            assert_eq!(
                (review, escalate, block, budget),
                (13, 25, 32, 3),
                "ADR 0040 thresholds"
            );
            assert!(debts.len() >= 40, "the G118 audit recorded 41 debts");
            for (id, block) in &debts {
                for field in [
                    "capability",
                    "required_end_state",
                    "current_support",
                    "current_evidence",
                    "known_unknowns",
                    "known_unsoundness",
                    "known_blind_spots",
                    "why_open",
                    "next_attack",
                    "attack_type",
                    "native_or_external",
                    "success_condition",
                    "falsification_condition",
                    "deadline_gate",
                    "risk_if_deferred",
                    "first_observed_note",
                    "escalation_state",
                ] {
                    text(block, field);
                }
                for field in [
                    "donors_examined",
                    "mechanisms_rejected",
                    "mechanisms_absorbed",
                    "external_boundaries",
                    "blocking_priorities",
                    "blocking_exit_criteria",
                    "blocking_milestones",
                ] {
                    list(block, field);
                }
                assert_eq!(text(block, "class"), "ESSENTIAL", "{id}");
                let priority = text(block, "priority");
                assert!(
                    ["P0", "P1", "P2", "P3", "P4", "P5", "P6", "END_STATE"]
                        .contains(&priority.as_str()),
                    "{id}: priority {priority}"
                );
                assert!(
                    [
                        "NATIVE_IMPLEMENTATION",
                        "NATIVE_MEASUREMENT",
                        "BOUNDARY_ADAPTER",
                        "ORACLE_INTEGRATION"
                    ]
                    .contains(&text(block, "attack_type").as_str()),
                    "{id}: attack_type"
                );
                assert!(
                    ["NATIVE", "EXTERNAL_BOUNDARY", "NATIVE_ABOVE_EXTERNAL"]
                        .contains(&text(block, "native_or_external").as_str()),
                    "{id}: native_or_external"
                );
                let rank = |field: &str| {
                    let level = text(block, field);
                    MATURITY
                        .iter()
                        .position(|m| *m == level)
                        .unwrap_or_else(|| panic!("{id}: {field} {level}"))
                };
                assert!(
                    rank("current_maturity") <= rank("required_maturity"),
                    "{id}"
                );
                let first = generation(&text(block, "first_observed_generation"));
                let last = generation(&text(block, "last_advance_generation"));
                assert!(
                    first <= last && last <= current,
                    "{id}: {first} {last} {current}"
                );
                assert_eq!(
                    generation(&text(block, "current_generation")),
                    as_of,
                    "{id}: current_generation"
                );
                assert_eq!(number(block, "age_generations"), as_of - first, "{id}: age");
                assert_eq!(
                    number(block, "stale_generations"),
                    as_of - last,
                    "{id}: stale"
                );
                let blocked_by = list(block, "blocked_by");
                for blocker in &blocked_by {
                    assert!(debts.contains_key(blocker), "{id}: blocked_by {blocker}");
                }
                let frozen = flag(block, "frozen");
                if frozen {
                    text(block, "unfreeze_gate");
                }
                let state = text(block, "current_state");
                match state.as_str() {
                    // Anti-avoidance: a debt closes only natively, at a permanent boundary or by a
                    // proven alternative, citing evidence in the repository -- never a donor verdict.
                    "CLOSED" => {
                        let kind = text(block, "closure_kind");
                        assert!(
                            [
                                "NATIVE_SOLUTION",
                                "PERMANENT_EXTERNAL_BOUNDARY",
                                "PROVEN_ALTERNATIVE"
                            ]
                            .contains(&kind.as_str()),
                            "{id}: closure_kind {kind}"
                        );
                        let evidence = text(block, "closure_evidence");
                        let path = evidence.split_whitespace().next().unwrap();
                        assert!(root().join(path).exists(), "{id}: closure evidence {path}");
                        continue;
                    }
                    "BOUNDED_RESIDUAL" | "OPEN" => {}
                    other => panic!("{id}: state {other}"),
                }
                let stale = current - last;
                // The recorded escalation state is the state as of the ledger's `ages_as_of`.
                assert_eq!(
                    text(block, "escalation_state"),
                    escalation(as_of - last, &ledger.header),
                    "{id}: escalation_state"
                );
                let reviewed = generation(&text(block, "reviewed_in"));
                if stale >= review {
                    assert!(
                        current - reviewed < review,
                        "{id}: REVIEW_REQUIRED -- stale {stale} generations, last reviewed G{reviewed}"
                    );
                }
                let planned = queued.contains_key(id)
                    || blocked_by.iter().any(|b| queued.contains_key(b))
                    || frozen;
                if state == "OPEN" {
                    let triggered = non_advancing_streak(id, last) >= budget;
                    assert_eq!(
                        flag(block, "skip_budget_triggered"),
                        triggered,
                        "{id}: skip budget recomputed from the donor audit"
                    );
                    if stale >= escalate || triggered {
                        assert!(
                            planned,
                            "{id}: alarmed debt must be queued, blocked by a queued debt, or frozen with an unfreeze gate"
                        );
                    }
                }
            }
        }

        /// G120: a generation's semantic metrics are derived from its own pre/post census
        /// snapshots, never hand-maintained. Every `[[generation.metric]]` names a snapshot total;
        /// `after` must equal the post-change total, and `before` the pre-change total (omitted only
        /// when the pre snapshot predates that total's existence). From G120 every NATIVE_ATTACK
        /// generation carries metrics, and a completed attack's result states no free numbers.
        #[test]
        fn generation_metrics_are_derived_from_snapshots() {
            let snapshot = |path: &str| -> serde_json::Value {
                serde_json::from_str(&read(path)).unwrap_or_else(|e| panic!("{path}: {e}"))
            };
            for (id, block) in ledger_generations() {
                let metrics = blocks(&block, "generation.metric");
                if generation(&id) >= 120
                    && ["NATIVE_ATTACK", "COMPOSITION_ATTACK"]
                        .contains(&text(&block, "kind").as_str())
                {
                    assert!(
                        !metrics.is_empty(),
                        "{id}: a native attack states derived metrics"
                    );
                }
                if metrics.is_empty() {
                    continue;
                }
                let report = text(&block, "self_recensus");
                let dir = &report[..report.rfind('/').unwrap()];
                let pre = snapshot(&format!("{dir}/pre.json"));
                let post = snapshot(&format!("{dir}/post.json"));
                for metric in metrics {
                    let key = text(metric, "key");
                    let after = post["totals"][&key]
                        .as_i64()
                        .unwrap_or_else(|| panic!("{id}: post.json has no total `{key}`"));
                    assert_eq!(number(metric, "after"), after, "{id}: {key} after");
                    match pre["totals"][&key].as_i64() {
                        Some(before) => {
                            assert_eq!(number(metric, "before"), before, "{id}: {key} before")
                        }
                        None => assert!(
                            raw(metric, "before").is_none(),
                            "{id}: {key} has no pre-change total to derive `before` from"
                        ),
                    }
                }
            }
            let ledger = Ledger::load();
            for done in blocks(&ledger.text, "native_attack_done") {
                if generation(&text(done, "generation")) >= 120 {
                    assert!(
                        !text(done, "result").chars().any(|c| c.is_ascii_digit()),
                        "{}: numbers belong in generation.metric entries",
                        text(done, "id")
                    );
                }
            }
            // The G119 metric correction stays backed by its reproducible evidence.
            let reconciliation: serde_json::Value = serde_json::from_str(&read(
                ".atlas/evidence/census/G119/call-metric-reconciliation.json",
            ))
            .unwrap();
            let delta = reconciliation["g119_call_record_delta"].as_i64().unwrap();
            let parts = reconciliation["g119_new_code_call_sites"].as_i64().unwrap()
                + reconciliation["g119_macro_argument_call_sites"]
                    .as_i64()
                    .unwrap();
            assert_eq!(delta, parts, "the G119 decomposition adds up");
            assert_eq!(
                delta,
                reconciliation["c_g119_extractor_on_g119_tree"]
                    .as_i64()
                    .unwrap()
                    - reconciliation["a_g118_extractor_on_g118_tree"]
                        .as_i64()
                        .unwrap()
            );
        }

        /// G121 (ADR 0043): a historical donor verdict is valid only for the capabilities that
        /// produced it. The trigger status of every audited donor is recomputed here from the
        /// capability milestones -- never from generation age -- and every executed revalidation
        /// must name its debt and question, pin the exact historical commit, carry its
        /// historical-vs-current evidence, end in a defined outcome, and leave no donor source.
        #[test]
        fn historical_donor_revalidation_triggers_are_capability_based() {
            let text_all = read(REVALIDATION);
            let header = text_all.split("\n[[").next().unwrap();
            assert!(
                text(header, "rule").starts_with(
                    "A historical donor verdict is valid evidence only for the semantic capabilities available at the time it was produced."
                ),
                "the hard rule for old OSS evidence is canonical"
            );
            let ledger = Ledger::load();
            let debts = ledger.debts();
            assert_eq!(
                text(header, "evaluated_at"),
                text(&ledger.header, "ages_as_of"),
                "priorities use the ledger's ages"
            );
            let generations: BTreeSet<String> =
                ledger_generations().into_iter().map(|(id, _)| id).collect();
            let milestones: Vec<(String, i64, Vec<String>, Vec<String>)> =
                blocks(&text_all, "capability_milestone")
                    .into_iter()
                    .map(|b| {
                        let id = text(b, "id");
                        let at = text(b, "generation");
                        assert!(
                            generations.contains(&at),
                            "{id}: {at} is not a ledger generation"
                        );
                        let named = list(b, "debts");
                        for debt in &named {
                            assert!(debts.contains_key(debt), "{id}: {debt}");
                        }
                        text(b, "evidence");
                        (id, generation(&at), named, list(b, "languages"))
                    })
                    .collect();
            let revalidations = blocks(&text_all, "revalidation");
            let audited: BTreeMap<String, String> =
                donors().into_iter().map(|d| (d.name, d.block)).collect();
            let entries = blocks(&text_all, "donor");
            assert_eq!(
                entries.len(),
                audited.len(),
                "every audited donor is evaluated"
            );
            let mut required: Vec<(i64, String, i64)> = Vec::new();
            for entry in &entries {
                let donor = text(entry, "donor");
                let audit = audited
                    .get(&donor)
                    .unwrap_or_else(|| panic!("{donor}: not an audited donor"));
                let donor_debts = list(audit, "debts");
                assert_eq!(list(entry, "capabilities_examined"), donor_debts, "{donor}");
                let decided = generation(&text(audit, "decided_in"));
                let revalidated_at = revalidations
                    .iter()
                    .filter(|r| text(r, "donor") == donor)
                    .map(|r| generation(&text(r, "generation")))
                    .max();
                let last_census = decided.max(revalidated_at.unwrap_or(0));
                let language = text(entry, "language");
                let candidate: Vec<&(String, i64, Vec<String>, Vec<String>)> = milestones
                    .iter()
                    .filter(|(_, at, named, _)| {
                        *at > last_census && named.iter().any(|d| donor_debts.contains(d))
                    })
                    .collect();
                let observable = candidate
                    .iter()
                    .any(|(_, _, _, languages)| languages.contains(&language));
                let (status, delta): (&str, Vec<String>) = if number(audit, "first_50_ordinal") == 0
                {
                    ("NOT_A_HISTORICAL_DECISION", Vec::new())
                } else if candidate.is_empty() {
                    (
                        if revalidated_at.is_some() {
                            "REVALIDATED"
                        } else {
                            "CURRENT"
                        },
                        Vec::new(),
                    )
                } else {
                    let ids: Vec<String> = candidate.iter().map(|m| m.0.clone()).collect();
                    if language == "undetermined" {
                        ("LANGUAGE_UNDETERMINED", ids)
                    } else if !observable {
                        ("CAPABILITY_NOT_APPLICABLE", ids)
                    } else {
                        ("REVALIDATION_REQUIRED", ids)
                    }
                };
                assert_eq!(text(entry, "status"), status, "{donor}: trigger status");
                assert_eq!(
                    list(entry, "semantic_delta"),
                    delta,
                    "{donor}: semantic delta"
                );
                text(entry, "reason");
                if status == "REVALIDATION_REQUIRED" {
                    let priority: i64 = candidate
                        .iter()
                        .map(|(_, _, named, _)| {
                            named
                                .iter()
                                .filter(|d| donor_debts.contains(d))
                                .map(|d| number(debts[d.as_str()], "age_generations"))
                                .sum::<i64>()
                        })
                        .sum();
                    assert_eq!(number(entry, "priority"), priority, "{donor}: priority");
                    required.push((-priority, donor.clone(), number(entry, "rank")));
                } else {
                    assert_eq!(number(entry, "rank"), 0, "{donor}");
                }
            }
            required.sort();
            for (index, (_, donor, rank)) in required.iter().enumerate() {
                assert_eq!(*rank, index as i64 + 1, "{donor}: rank by priority");
            }
            // Executed revalidations: a new decision layer, never a rewritten history.
            let queue = ledger.attack_ids();
            for r in &revalidations {
                let id = text(r, "id");
                let donor = text(r, "donor");
                let audit = &audited[&donor];
                assert!(
                    number(audit, "first_50_ordinal") > 0,
                    "{id}: not a historical donor"
                );
                let debt = text(r, "debt");
                assert!(
                    list(audit, "debts").contains(&debt),
                    "{id}: {debt} is not what the verdict depended on"
                );
                // Every capability cited must advance a debt the historical verdict depended on.
                let depended = list(audit, "debts");
                for capability in list(r, "capabilities") {
                    assert!(
                        milestones
                            .iter()
                            .any(|m| m.0 == capability && m.2.iter().any(|d| depended.contains(d))),
                        "{id}: {capability} advances no debt the verdict depended on"
                    );
                }
                text(r, "question");
                let pinned = text(r, "pinned_commit");
                assert_eq!(pinned.len(), 40, "{id}: a full commit id");
                let historical = std::fs::read_dir(root().join(".atlas/evidence/campaign"))
                    .unwrap()
                    .filter_map(|e| e.ok())
                    .find(|e| {
                        e.file_name()
                            .to_string_lossy()
                            .ends_with(&format!("-{donor}.json"))
                    })
                    .map(|e| std::fs::read_to_string(e.path()).unwrap())
                    // A donor decided before the First-50 campaign (souffle, datafrog, blake3)
                    // has its historical pin in its provenance record instead.
                    .or_else(|| {
                        std::fs::read_to_string(
                            root().join(format!(".atlas/provenance/donors/{donor}.json")),
                        )
                        .ok()
                    })
                    .unwrap_or_else(|| panic!("{id}: no historical campaign evidence for {donor}"));
                let historical: serde_json::Value = serde_json::from_str(&historical).unwrap();
                assert_eq!(
                    historical["commit_sha"].as_str(),
                    Some(pinned.as_str()),
                    "{id}: the EXACT historical pin"
                );
                let outcome = text(r, "outcome");
                assert!(
                    ["REVALIDATED", "MECHANISM_FOUND", "DEBT_REOPENED"].contains(&outcome.as_str()),
                    "{id}: outcome {outcome}"
                );
                let evidence: serde_json::Value =
                    serde_json::from_str(&read(&text(r, "evidence"))).unwrap();
                assert_eq!(evidence["donor"].as_str(), Some(donor.as_str()), "{id}");
                assert_eq!(evidence["outcome"].as_str(), Some(outcome.as_str()), "{id}");
                assert_eq!(
                    evidence["materialization"]["pinned_commit"].as_str(),
                    Some(pinned.as_str()),
                    "{id}"
                );
                assert_eq!(
                    evidence["engines"]["same_source"].as_bool(),
                    Some(true),
                    "{id}: one source, both engines"
                );
                assert!(
                    evidence["crate_census"]["historical_records"].is_object(),
                    "{id}: historical census"
                );
                assert!(
                    evidence["crate_census"]["current_records"].is_object(),
                    "{id}: current census"
                );
                assert_eq!(
                    evidence["decision_layer"]["historical_record_rewritten"].as_bool(),
                    Some(false)
                );
                let generation_id = text(r, "generation");
                let (_, block) = ledger_generations()
                    .into_iter()
                    .find(|(g, _)| *g == generation_id)
                    .unwrap_or_else(|| panic!("{id}: {generation_id} not in the ledger"));
                // A donor Gundam proof is an agent mission that carries a revalidation (G136); a
                // replay at the donor's exact historical pin carries one too (G156, ADR 0067:
                // every replay is an Agent-Worn mission).
                assert!(
                    ["REVALIDATION", "AGENT_MISSION", "REPLAY"]
                        .contains(&text(&block, "kind").as_str()),
                    "{id}"
                );
                let follow_up = text(r, "follow_up");
                assert!(
                    queue.contains(&follow_up) || debts.contains_key(&follow_up),
                    "{id}: follow-up {follow_up} is neither a native attack nor a debt"
                );
                if outcome == "DEBT_REOPENED" {
                    assert_eq!(text(debts[debt.as_str()], "current_state"), "OPEN", "{id}");
                }
                match text(r, "status").as_str() {
                    "COMPLETE" => assert!(
                        !root().join(text(r, "source_path")).exists(),
                        "{id}: the donor source must be physically deleted again"
                    ),
                    "IN_PROGRESS" => {}
                    other => panic!("{id}: status {other}"),
                }
            }
        }

        #[test]
        fn essential_debt_has_explicit_next_attack() {
            let ledger = Ledger::load();
            let debts = ledger.debts();
            let attacks = ledger.attack_ids();
            for (id, block) in &debts {
                let next = text(block, "next_attack");
                assert!(
                    !is_vague(&next),
                    "{id}: next_attack `{next}` is not an attack"
                );
                let named: Vec<&str> = next
                    .split(|c: char| !(c.is_ascii_alphanumeric() || c == '-' || c == '_'))
                    .filter(|w| w.starts_with("NA-") || w.starts_with("DEBT-"))
                    .collect();
                assert!(
                    !named.is_empty() || next.starts_with("frozen"),
                    "{id}: next_attack names no native attack, blocking debt, or freeze: {next}"
                );
                for word in named {
                    if word.starts_with("NA-") {
                        assert!(attacks.contains(word), "{id}: unknown attack {word}");
                    } else {
                        assert!(debts.contains_key(word), "{id}: unknown debt {word}");
                    }
                }
                for field in ["success_condition", "falsification_condition"] {
                    assert!(!is_vague(&text(block, field)), "{id}: vague {field}");
                }
            }
        }

        #[test]
        fn essential_debt_has_deadline_gate() {
            let ledger = Ledger::load();
            let nodes: BTreeSet<String> = blocks(&ledger.text, "construction_node")
                .into_iter()
                .map(|b| text(b, "id"))
                .collect();
            for (id, block) in ledger.debts() {
                let gate = text(block, "deadline_gate");
                assert!(!is_vague(&gate), "{id}: deadline_gate `{gate}`");
                assert!(
                    nodes.contains(&gate)
                        || [
                            "FOUNDATIONAL_ATLAS_READY",
                            "SEALED .atlas",
                            "ASIR admission",
                            "unfreeze gate"
                        ]
                        .contains(&gate.as_str()),
                    "{id}: deadline_gate `{gate}` is not a named gate or construction milestone"
                );
            }
        }

        #[test]
        fn native_attack_queue_is_ordered_and_heads_selection() {
            let ledger = Ledger::load();
            let debts = ledger.debts();
            let attacks = blocks(&ledger.text, "native_attack");
            assert!(!attacks.is_empty(), "the native attack queue is empty");
            let mut ids = BTreeSet::new();
            for (index, block) in attacks.iter().enumerate() {
                assert_eq!(
                    number(block, "position"),
                    index as i64 + 1,
                    "contiguous order"
                );
                assert!(ids.insert(text(block, "id")), "attack id twice");
                text(block, "objective");
                flag(block, "bounded");
                let priority = text(block, "priority");
                assert!(
                    ["P0", "P1", "P2", "P3", "P4", "P5", "P6"].contains(&priority.as_str()),
                    "{priority}"
                );
                let named = list(block, "debts");
                assert!(!named.is_empty());
                for debt in named {
                    let target = debts
                        .get(&debt)
                        .unwrap_or_else(|| panic!("attack names unknown {debt}"));
                    assert_ne!(text(target, "current_state"), "CLOSED", "{debt} is closed");
                }
            }
            for done in blocks(&ledger.text, "native_attack_done") {
                let generation_id = text(done, "generation");
                assert!(
                    ledger_generations()
                        .iter()
                        .any(|(id, _)| *id == generation_id),
                    "done attack names unknown {generation_id}"
                );
            }
            // Rule B: the queue head is the next generation's plan and PRIORITY.toml names it.
            let head = attacks[0];
            let priority = read(".atlas/roadmap/PRIORITY.toml");
            assert_eq!(
                string(&priority, "next_native_attack"),
                string(head, "id"),
                "PRIORITY.toml next_native_attack must be the queue head"
            );
            // Rule B: the head is the next generation -- or the one after it when PRIORITY.toml
            // plans exactly the next one as an interleaving generation: a
            // HISTORICAL_DONOR_REVALIDATION (G121+), an AGENT_MISSION or a
            // DEBT_TRIGGERED_DONOR_ATTACK (G122+, ADR 0044).
            let current = current_generation();
            let planned = generation(&text(head, "planned_generation"));
            let interleaving_next = blocks(&priority, "planned_generation").iter().any(|b| {
                string(b, "id") == Some(format!("G{}", current + 1))
                    && string(b, "objective").is_some_and(|o| {
                        [
                            "HISTORICAL_DONOR_REVALIDATION",
                            "AGENT_MISSION",
                            "DEBT_TRIGGERED_DONOR_ATTACK",
                            "FULL_OSS_REPLAY",
                        ]
                        .iter()
                        .any(|class| o.starts_with(class))
                    })
            });
            assert!(
                planned == current + 1 || (planned == current + 2 && interleaving_next),
                "the queue head is planned for the next native generation (G{planned} at G{current})"
            );
            // Dependency order before pressure (tightened G124): the head's primary debt is not
            // blocked by another open debt -- nor (G145) confined to construction nodes whose
            // requirements are missing -- and among such bounded attacks the head carries the
            // largest summed stale_generations.
            let nodes = blocks(&ledger.text, "construction_node");
            let status: BTreeMap<String, String> = nodes
                .iter()
                .map(|block| (text(block, "id"), text(block, "status")))
                .collect();
            let reachable = |debt: &str| {
                let owned: Vec<bool> = nodes
                    .iter()
                    .filter(|b| text(b, "status") == "MISSING" && text(b, "debt") == debt)
                    .map(|b| list(b, "requires").iter().all(|r| status[r] == "EXISTS"))
                    .collect();
                owned.is_empty() || owned.contains(&true)
            };
            let unblocked_primary = |attack: &str| {
                list(attack, "debts").first().is_some_and(|d| {
                    reachable(d)
                        && debts
                            .get(d)
                            .is_some_and(|b| list(b, "blocked_by").is_empty())
                })
            };
            let pressure = |attack: &str| -> i64 {
                list(attack, "debts")
                    .iter()
                    .filter_map(|d| debts.get(d))
                    .map(|b| number(b, "stale_generations"))
                    .sum()
            };
            assert!(
                unblocked_primary(head),
                "the queue head waits on a missing prerequisite"
            );
            for attack in &attacks {
                if flag(attack, "bounded") && unblocked_primary(attack) {
                    assert!(
                        pressure(attack) <= pressure(head),
                        "{} outweighs the queue head {}",
                        text(attack, "id"),
                        text(head, "id")
                    );
                }
            }
        }

        /// ADR 0044: interleaving generations never starve the native queue, and once the
        /// Agent-Worn interface exists an agent mission recurs at a bounded cadence.
        #[test]
        fn native_queue_is_never_starved_and_agent_missions_recur() {
            let priority = read(".atlas/roadmap/PRIORITY.toml");
            let worn = table(&priority, "agent_worn");
            let interleaving = list(worn, "interleaving_classes");
            let classes = list(worn, "generation_classes");
            let max_run = number(worn, "max_consecutive_interleaving");
            let every = number(worn, "agent_mission_every");
            let interface = generation(&text(worn, "interface_generation"));
            let mut run = 0;
            let mut last_mission = interface;
            for (id, block) in ledger_generations() {
                if generation(&id) < 116 {
                    continue;
                }
                let kind = text(&block, "kind");
                assert!(
                    classes.contains(&kind),
                    "{id}: {kind} is not a generation class"
                );
                run = if interleaving.contains(&kind) {
                    run + 1
                } else {
                    0
                };
                assert!(
                    run <= max_run,
                    "{id}: more than {max_run} consecutive interleaving generations"
                );
                // ADR 0067: every replay generation is an Agent-Worn mission on its donor.
                if kind == "AGENT_MISSION" || kind == "REPLAY" {
                    last_mission = generation(&id);
                }
            }
            let current = current_generation();
            assert!(
                current - last_mission <= every,
                "no AGENT_MISSION for {} generations (G{last_mission} at G{current})",
                current - last_mission
            );
            // The generation that opened the interface composed the census.
            let (_, block) = ledger_generations()
                .into_iter()
                .find(|(id, _)| generation(id) == interface)
                .expect("the interface generation is in the ledger");
            assert_eq!(text(&block, "kind"), "COMPOSITION_ATTACK");
        }

        #[test]
        fn all_donor_corpus_records_have_capability_classification() {
            let corpus = read(".atlas/references/donor-corpus.toml");
            let corpus_ids: BTreeSet<String> = blocks(&corpus, "donor")
                .into_iter()
                .map(|b| text(b, "id"))
                .collect();
            let campaign = read(".atlas/roadmap/FIRST-50-CAMPAIGN.toml");
            let first_50: BTreeMap<String, String> = blocks(&campaign, "donor")
                .into_iter()
                .map(|b| (text(b, "repository"), text(b, "terminal_state")))
                .collect();
            let audited = donors();
            let names: BTreeSet<String> = audited.iter().map(|d| d.name.clone()).collect();
            assert_eq!(names.len(), audited.len(), "a donor audited twice");
            let first_50_ids: BTreeSet<String> = first_50.keys().cloned().collect();
            let expected: BTreeSet<String> = corpus_ids.union(&first_50_ids).cloned().collect();
            assert_eq!(
                names, expected,
                "every corpus record and every First-50 donor is audited"
            );
            let header = read(AUDIT);
            let header = header.split("\n[[").next().unwrap();
            let outside = first_50.keys().filter(|d| !corpus_ids.contains(*d)).count() as i64;
            assert_eq!(
                number(header, "donor_corpus_records"),
                corpus_ids.len() as i64
            );
            assert_eq!(number(header, "first_50_donors"), first_50.len() as i64);
            assert_eq!(number(header, "first_50_outside_donor_corpus"), outside);
            assert_eq!(
                number(header, "donor_corpus_outside_first_50"),
                corpus_ids
                    .iter()
                    .filter(|d| !first_50.contains_key(*d))
                    .count() as i64
            );
            assert_eq!(number(header, "donors_audited"), audited.len() as i64);
            let known = Ledger::load().known_ids();
            let mut suspicious = BTreeSet::new();
            for donor in &audited {
                let (name, block) = (&donor.name, &donor.block);
                assert_eq!(
                    flag(block, "in_donor_corpus"),
                    corpus_ids.contains(name),
                    "{name}"
                );
                let mechanism = text(block, "mechanism_decision");
                assert!(
                    TERMINAL.contains(&mechanism.as_str()) || mechanism == "DEFERRED",
                    "{name}: mechanism_decision {mechanism}"
                );
                let capability = text(block, "capability_decision");
                assert!(
                    [
                        "CAPABILITY_CLOSED",
                        "CAPABILITY_PARTIAL",
                        "CAPABILITY_OPEN_ESSENTIAL",
                        "CAPABILITY_OPEN_SCALE_TRIGGERED",
                        "CAPABILITY_NOT_REQUIRED"
                    ]
                    .contains(&capability.as_str()),
                    "{name}: capability_decision {capability}"
                );
                if let Some(state) = first_50.get(name) {
                    let expected = if mechanism.starts_with("REFERENCE_ONLY") {
                        "REFERENCE_ONLY"
                    } else {
                        mechanism.as_str()
                    };
                    assert_eq!(state, expected, "{name}: campaign terminal state");
                }
                for debt in list(block, "debts") {
                    assert!(known.contains(&debt), "{name}: unknown debt {debt}");
                }
                if mechanism == "DEFERRED" {
                    for field in [
                        "deferred_trigger",
                        "deferred_owner",
                        "deferred_milestone",
                        "deferred_readmission",
                    ] {
                        assert!(!is_vague(&text(block, field)), "{name}: {field}");
                    }
                }
                if mechanism == "REFERENCE_ONLY_UNTIL_TRIGGER" {
                    let trigger = text(block, "trigger");
                    assert!(!is_vague(&trigger), "{name}: `later` is not a trigger");
                    assert!(
                        trigger.contains("milestone")
                            || trigger.chars().any(|c| c.is_ascii_digit())
                            || known.iter().any(|id| trigger.contains(id.as_str())),
                        "{name}: trigger names no number, milestone or debt: {trigger}"
                    );
                }
                if flag(block, "conflated") {
                    text(block, "conflation_quote");
                }
                if raw(block, "suspicious_case").is_some() {
                    suspicious.insert(name.clone());
                    let answer = text(block, "mechanism_unnecessary");
                    assert!(
                        ["YES", "NO", "NOT_YET"].contains(&answer.as_str()),
                        "{name}: {answer}"
                    );
                    // Was THIS mechanism unnecessary, AND is the capability still required: the
                    // second answer follows the capability decision, never the donor verdict.
                    assert_eq!(
                        flag(block, "capability_still_required"),
                        capability != "CAPABILITY_NOT_REQUIRED",
                        "{name}"
                    );
                }
            }
            for name in [
                "differential-dataflow",
                "buck2",
                "egglog",
                "joern",
                "miri",
                "mlir",
                "xdsl",
                "wasm-spec",
                "wasm-component-model",
                "wasm-tools",
                "wasmtime",
                "llvm-project",
                "regalloc2",
                "mold",
                "kani",
                "verus",
                "z3",
                "tlaplus",
                "nix",
                "openrewrite",
                "c2rust",
                "salsa",
            ] {
                assert!(
                    suspicious.contains(name),
                    "{name}: suspicious case not re-audited"
                );
            }
        }

        #[test]
        fn donor_terminal_does_not_close_capability() {
            let ledger = Ledger::load();
            let debts = ledger.debts();
            for donor in donors() {
                let block = &donor.block;
                let linked = list(block, "debts");
                if text(block, "capability_decision") == "CAPABILITY_CLOSED" {
                    assert!(
                        !linked.is_empty()
                            && linked.iter().all(|d| debts
                                .get(d)
                                .is_some_and(|b| text(b, "current_state") == "CLOSED")),
                        "{}: a donor decision cannot close a capability whose debt is open",
                        donor.name
                    );
                }
                if matches!(
                    text(block, "capability_decision").as_str(),
                    "CAPABILITY_OPEN_ESSENTIAL" | "CAPABILITY_PARTIAL"
                ) {
                    assert!(
                        linked.iter().any(|d| debts
                            .get(d)
                            .is_some_and(|b| text(b, "current_state") != "CLOSED")),
                        "{}: an open capability needs an open debt",
                        donor.name
                    );
                }
            }
        }

        #[test]
        fn reference_only_does_not_mean_capability_unnecessary() {
            let audit = read(AUDIT);
            let optional: BTreeSet<String> = blocks(&audit, "donor_cluster")
                .into_iter()
                .filter(|b| text(b, "class") == "OPTIONAL")
                .map(|b| text(b, "id"))
                .collect();
            for donor in donors() {
                let block = &donor.block;
                if text(block, "capability_decision") == "CAPABILITY_NOT_REQUIRED" {
                    assert!(
                        optional.contains(&text(block, "capability_cluster")),
                        "{}: CAPABILITY_NOT_REQUIRED only in an OPTIONAL cluster",
                        donor.name
                    );
                    assert!(list(block, "debts").is_empty(), "{}", donor.name);
                }
                // `no consumer` is a reason only for OPTIONAL, or SCALE_TRIGGERED with a trigger.
                let reasoning = format!(
                    "{} {}",
                    string(block, "note").unwrap_or_default(),
                    string(block, "conflation_quote").unwrap_or_default()
                )
                .to_ascii_lowercase();
                if reasoning.contains("consumer")
                    && matches!(
                        text(block, "capability_decision").as_str(),
                        "CAPABILITY_OPEN_ESSENTIAL" | "CAPABILITY_PARTIAL"
                    )
                {
                    assert!(
                        flag(block, "conflated"),
                        "{}: `no consumer` used against essential complexity must be recorded as drift",
                        donor.name
                    );
                }
            }
        }

        #[test]
        fn external_boundaries_have_boundary_class() {
            for donor in donors() {
                if text(&donor.block, "mechanism_decision") == "EXTERNAL_BOUNDARY" {
                    let kind = text(&donor.block, "boundary_type");
                    assert!(
                        BOUNDARY_TYPES.contains(&kind.as_str()),
                        "{}: {kind}",
                        donor.name
                    );
                }
            }
            let ledger = Ledger::load();
            let debts = ledger.debts();
            for block in blocks(&ledger.text, "construction_component") {
                let id = text(block, "id");
                let debt = text(block, "debt");
                let owner = debts.get(&debt).unwrap_or_else(|| panic!("{id}: {debt}"));
                match text(block, "ownership").as_str() {
                    "NATIVE_REQUIRED" => {
                        if text(block, "status") != "IMPLEMENTED" {
                            assert_ne!(text(owner, "current_state"), "CLOSED", "{id}");
                        }
                    }
                    "EXTERNAL_BOUNDARY_ALLOWED" => {
                        let kind = text(block, "boundary_type");
                        assert!(BOUNDARY_TYPES.contains(&kind.as_str()), "{id}: {kind}");
                    }
                    other => panic!("{id}: ownership {other}"),
                }
            }
        }

        #[test]
        fn scale_triggered_debt_has_measurable_trigger() {
            let ledger = Ledger::load();
            let scale = ledger.scale_ids();
            let mut fired = BTreeMap::new();
            for block in blocks(&ledger.text, "scale_trigger") {
                let id = text(block, "id");
                assert!(id.starts_with("SCALE-"), "{id}");
                assert_eq!(text(block, "class"), "SCALE_TRIGGERED");
                let trigger = text(block, "trigger");
                assert!(!is_vague(&trigger), "{id}: vague trigger");
                assert!(
                    trigger.chars().any(|c| c.is_ascii_digit()),
                    "{id}: a scale trigger must name a number: {trigger}"
                );
                text(block, "current_measurement");
                fired.insert(id, text(block, "status") == "FIRED");
            }
            // Thresholds read from the post-change census are evaluated against the ledger head.
            let head = format!("G{}", current_generation());
            let post: serde_json::Value =
                serde_json::from_str(&read(&format!(".atlas/evidence/census/{head}/post.json")))
                    .expect("post.json");
            let mut evaluated = 0;
            for block in blocks(&ledger.text, "scale_threshold") {
                let trigger = text(block, "trigger");
                assert!(scale.contains(&trigger), "{trigger}");
                let threshold = number(block, "threshold");
                assert!(threshold > 0);
                let source = text(block, "source");
                if let Some(key) = source.strip_prefix("post.json:") {
                    let value = post["totals"][key]
                        .as_i64()
                        .unwrap_or_else(|| panic!("post.json totals has no {key}"));
                    if value > threshold {
                        assert!(
                            fired[&trigger],
                            "{trigger}: {key} {value} > {threshold} but NOT_FIRED"
                        );
                    }
                    evaluated += 1;
                } else {
                    assert!(source.starts_with("measured:"), "{source}");
                }
            }
            assert!(
                evaluated >= 4,
                "census-size thresholds are mechanically evaluated"
            );
        }

        #[test]
        fn first_50_complete_is_not_foundational_ready() {
            let gate = read(GATE);
            let first_50 = table(&gate, "first_50_campaign_complete");
            let foundational = table(&gate, "foundational_atlas_ready");
            let criteria = blocks(&gate, "criterion");
            assert_eq!(criteria.len(), 10, "the contract's ten criteria");
            let all_met = criteria.iter().all(|c| {
                let status = text(c, "status");
                assert!(["MET", "NOT_MET"].contains(&status.as_str()), "{status}");
                status == "MET"
            });
            assert_eq!(
                flag(foundational, "value"),
                all_met,
                "foundational = all criteria"
            );
            assert_eq!(
                text(foundational, "status"),
                if all_met { "MET" } else { "NOT_MET" }
            );
            // The campaign gate never stands in for the foundational one.
            let campaign = read(".atlas/roadmap/FIRST-50-CAMPAIGN.toml");
            let remaining: i64 = blocks(&campaign, "donor")
                .iter()
                .filter(|b| text(b, "lifecycle") != "TERMINAL")
                .count() as i64;
            assert_eq!(flag(first_50, "value"), remaining == 0);
            let priority = read(".atlas/roadmap/PRIORITY.toml");
            let exit = string(&priority, "J_foundational_atlas_ready").expect("exit J");
            assert!(
                exit.starts_with(&text(foundational, "status")),
                "exit J restates the gate"
            );
            if !all_met {
                assert_eq!(
                    raw(&priority, "frontier_expansion_frozen").map(str::trim),
                    Some("true"),
                    "the frontier stays frozen until FOUNDATIONAL_ATLAS_READY"
                );
                assert_eq!(
                    text(table(&gate, "frontier_expansion"), "status"),
                    "BLOCKED"
                );
            }
            let g = string(&priority, "G_first_50_sequential_lifecycle_substantial").unwrap();
            assert!(
                g.contains("not FOUNDATIONAL_ATLAS_READY"),
                "exit G must not read as foundational readiness"
            );
        }

        #[test]
        fn frontier_expansion_blocked_until_audit_complete() {
            let gate = read(GATE);
            let frontier_gate = table(&gate, "frontier_expansion");
            if text(frontier_gate, "status") != "BLOCKED" {
                assert_eq!(
                    text(table(&gate, "foundational_atlas_ready"), "status"),
                    "MET"
                );
                return;
            }
            let frontier = read(".atlas/roadmap/RECOMMENDED-OSS-FRONTIER.toml");
            let repositories = blocks(&frontier, "repository");
            assert_eq!(
                repositories.len() as i64,
                number(frontier_gate, "pinned_repositories"),
                "the frontier grew while expansion is BLOCKED"
            );
            let mut lifecycles: BTreeMap<String, i64> = BTreeMap::new();
            for block in &repositories {
                *lifecycles.entry(text(block, "lifecycle")).or_default() += 1;
            }
            for (lifecycle, count) in &lifecycles {
                assert_eq!(
                    number(
                        frontier_gate,
                        &format!("pinned_lifecycle_{}", lifecycle.to_ascii_lowercase())
                    ),
                    *count,
                    "frontier lifecycle {lifecycle} changed while expansion is BLOCKED"
                );
            }
        }

        #[test]
        fn remaining_donor_corpus_progress_blocked_until_audit_complete() {
            let gate = read(GATE);
            let progression = table(&gate, "donor_progression");
            let blocked = donor_progression_blocked();
            assert_eq!(
                text(progression, "status") == "BLOCKED",
                blocked,
                "[donor_progression] status must equal the recomputed state"
            );
            let recorded: BTreeSet<String> =
                list(progression, "blocking_debts").into_iter().collect();
            let computed: BTreeSet<String> = progression_blockers().into_iter().collect();
            assert_eq!(
                recorded, computed,
                "blocking_debts must equal the recomputed blockers"
            );
            if !blocked {
                return;
            }
            // No donor-corpus record moves while progression is blocked.
            let corpus = read(".atlas/references/donor-corpus.toml");
            let records: BTreeMap<String, &str> = blocks(&corpus, "donor")
                .into_iter()
                .map(|b| (text(b, "id"), b))
                .collect();
            for donor in donors() {
                let Some(record) = records.get(&donor.name) else {
                    continue;
                };
                for field in [
                    "decision_status",
                    "ingestion_status",
                    "census_status",
                    "storage_state",
                ] {
                    assert_eq!(
                        string(record, field).unwrap_or_default(),
                        string(&donor.block, &format!("corpus_{field}")).unwrap_or_default(),
                        "{}: donor-corpus {field} changed while donor progression is BLOCKED",
                        donor.name
                    );
                }
            }
            assert_eq!(
                records.len(),
                donors()
                    .iter()
                    .filter(|d| flag(&d.block, "in_donor_corpus"))
                    .count(),
                "a donor-corpus record was added while blocked"
            );
            // No new donor checkout is materialized.
            let pinned: BTreeSet<String> = list(progression, "materialized_checkouts")
                .into_iter()
                .collect();
            let donors_dir = root().join(".atlas/temporary/donors");
            if donors_dir.is_dir() {
                for entry in std::fs::read_dir(&donors_dir).unwrap() {
                    let name = entry.unwrap().file_name().to_string_lossy().into_owned();
                    // HISTORICAL_DONOR_REVALIDATION (G121) may hold one transient checkout while its
                    // revalidation is IN_PROGRESS; a completed one is physically deleted again.
                    let transient = in_progress_revalidation_paths()
                        .iter()
                        .any(|p| p.ends_with(&format!("/{name}")));
                    assert!(
                        pinned.contains(&name) || transient,
                        "donor checkout `{name}` materialized while BLOCKED"
                    );
                }
            }
            // No donor generation after the audit.
            let audit_generation = generation(&text(table(&gate, "audit"), "audit_generation"));
            for (id, block) in ledger_generations() {
                if generation(&id) < 116 {
                    continue;
                }
                let kind = text(&block, "kind");
                assert!(
                    [
                        "AUDIT",
                        "NATIVE_ATTACK",
                        "DONOR",
                        "REVALIDATION",
                        "COMPOSITION_ATTACK",
                        "AGENT_MISSION",
                        "DEBT_TRIGGERED_DONOR_ATTACK",
                        "REPLAY",
                        "SELF_RECONSTRUCTION"
                    ]
                    .contains(&kind.as_str()),
                    "{id}: kind {kind}"
                );
                // ADR 0044: a debt-triggered donor attack names an open essential debt, a
                // hypothesis and an exact pin, and leaves no source behind.
                if kind == "DEBT_TRIGGERED_DONOR_ATTACK" {
                    let ledger = Ledger::load();
                    let debts = ledger.debts();
                    let debt = text(&block, "debt");
                    let target = debts
                        .get(&debt)
                        .unwrap_or_else(|| panic!("{id}: unknown debt {debt}"));
                    assert_eq!(text(target, "class"), "ESSENTIAL", "{id}");
                    assert_ne!(text(target, "current_state"), "CLOSED", "{id}");
                    text(&block, "hypothesis");
                    assert_eq!(text(&block, "pinned_commit").len(), 40, "{id}: exact pin");
                    assert!(
                        !root().join(text(&block, "source_path")).exists(),
                        "{id}: the donor source must be deleted again"
                    );
                }
                // An agent mission records what Atlas knew and what the agent read by hand.
                if kind == "AGENT_MISSION" {
                    let mission: serde_json::Value =
                        serde_json::from_str(&read(&text(&block, "mission"))).unwrap();
                    for field in [
                        "mission",
                        "atlas_knew",
                        "unknown",
                        "manual_source_reads",
                        "gaps",
                    ] {
                        assert!(
                            !mission[field].is_null(),
                            "{id}: mission record lacks {field}"
                        );
                    }
                }
                // A REVALIDATION generation is historical recensus, never new-donor progression:
                // it must execute a triggered [[revalidation]] of a historical First-50 donor.
                if kind == "REVALIDATION" {
                    let revalidation = read(REVALIDATION);
                    assert!(
                        blocks(&revalidation, "revalidation")
                            .iter()
                            .any(|r| text(r, "generation") == id),
                        "{id}: a REVALIDATION generation without its revalidation record"
                    );
                    assert_eq!(
                        text(table(&gate, "historical_revalidation"), "status"),
                        "ALLOWED_WHEN_TRIGGERED"
                    );
                }
                // ADR 0067: a REPLAY generation is the FULL_OSS_REPLAY lane, never new-donor
                // progression: it replays one repository of the canonical replay ledger at an
                // exact pin, records its Agent-Worn mission, and leaves no source behind.
                if kind == "REPLAY" {
                    replay_generation_is_accounted(&id, &block);
                }
                // ADR 0069: a SELF_RECONSTRUCTION generation records its attempts in the lane's
                // ledger, each with a module and a report that validate.
                if kind == "SELF_RECONSTRUCTION" {
                    let ledger = read(SELF_RECONSTRUCTION);
                    let attempts: Vec<&str> = blocks(&ledger, "attempt")
                        .into_iter()
                        .filter(|a| text(a, "generation") == id)
                        .collect();
                    assert!(!attempts.is_empty(), "{id}: no attempt in the lane ledger");
                }
                if generation(&id) >= audit_generation {
                    assert_ne!(
                        kind, "DONOR",
                        "{id}: donor generation while donor progression is BLOCKED"
                    );
                    assert_ne!(
                        text(&block, "priority"),
                        "P3",
                        "{id}: P3 donor campaign while BLOCKED"
                    );
                }
            }
        }

        /// ADR 0071: the repository's support claims rest on a measured report and never exceed
        /// it; every subject the report places at L3 or above is claimed (a real capability is
        /// not hidden), and nothing below L3 is called semantically supported.
        #[test]
        fn support_claims_never_exceed_the_measured_levels() {
            use atlas_core::coverage::{SupportLevel, SupportReport, validate_claims};
            let ledger = read(".atlas/roadmap/SUPPORT-LEVELS.toml");
            let report: SupportReport =
                serde_json::from_str(&read(&text(&ledger, "measured_report"))).unwrap();
            assert_eq!(report.schema, atlas_core::coverage::SUPPORT_REPORT_SCHEMA);
            let claims: Vec<(String, SupportLevel)> = blocks(&ledger, "claim")
                .into_iter()
                .map(|b| {
                    let level = serde_json::from_value(serde_json::Value::String(text(b, "level")))
                        .unwrap_or_else(|e| panic!("{b}: {e}"));
                    (text(b, "subject"), level)
                })
                .collect();
            assert_eq!(
                validate_claims(&report, &claims),
                vec![],
                "claims above what was measured"
            );
            let claimed: BTreeSet<&str> = claims.iter().map(|(s, _)| s.as_str()).collect();
            for subject in report.subjects.iter().filter(|s| s.level.is_semantic()) {
                assert!(
                    claimed.contains(subject.subject.as_str()),
                    "{} is measured but unclaimed",
                    subject.subject
                );
            }
            let semantic: BTreeSet<String> = claims
                .iter()
                .filter(|(_, level)| level.is_semantic())
                .map(|(s, _)| s.clone())
                .collect();
            assert_eq!(
                semantic,
                list(&ledger, "semantically_supported")
                    .into_iter()
                    .collect::<BTreeSet<_>>(),
                "the ledger's semantically supported list is exactly the claims at L3 or above"
            );
        }

        const SELF_RECONSTRUCTION: &str = ".atlas/roadmap/SELF-RECONSTRUCTION.toml";

        /// ADR 0069: the SELF_RECONSTRUCTION lane is its own lane with Rust as the bootstrap
        /// target; every attempt's module and report validate (construction read census records,
        /// a design and a comparison only; the verdict is the one its evidence supports); every
        /// gap is owned by a debt; a gap the latest attempt still has feeds a queued attack; a
        /// level is reached only by a reconstruction, and shadows live where nothing is admitted.
        #[test]
        fn self_reconstruction_keeps_its_boundary_and_feeds_its_gaps_back() {
            use atlas_core::construction::{
                ConstructionModule, ReconstructionVerdict, SelfReconstructionReport,
                validate_report,
            };
            let ledger = read(SELF_RECONSTRUCTION);
            assert_eq!(text(&ledger, "lane"), "SELF_RECONSTRUCTION");
            for other in [
                "FULL_OSS_REPLAY",
                "NEW_DONOR_PROGRESSION",
                "FRONTIER_EXPANSION",
                "HISTORICAL_DONOR_REVALIDATION",
                "NATIVE_ATTACK",
            ] {
                assert!(list(&ledger, "distinct_from").contains(&other.to_string()));
            }
            assert_eq!(
                text(&ledger, "bootstrap_construction_target"),
                atlas_core::construction::BOOTSTRAP_CONSTRUCTION_TARGET
            );
            let shadow_root = text(&ledger, "shadow_root");
            assert_eq!(shadow_root, crate::self_reconstruction::SHADOW_ROOT);
            assert!(
                read(".gitignore")
                    .lines()
                    .any(|l| shadow_root.starts_with(l.trim_start_matches('/'))
                        && !l.trim().is_empty()),
                "the shadow root is never tracked"
            );
            let debt_ledger = Ledger::load();
            let debts = debt_ledger.debts();
            let queued: BTreeSet<String> = blocks(&debt_ledger.text, "native_attack")
                .into_iter()
                .map(|b| text(b, "id"))
                .collect();
            let attempts = blocks(&ledger, "attempt");
            assert!(!attempts.is_empty());
            let mut reconstructed = false;
            for attempt in &attempts {
                let id = text(attempt, "id");
                let module: ConstructionModule =
                    serde_json::from_str(&read(&text(attempt, "module"))).unwrap();
                let report: SelfReconstructionReport =
                    serde_json::from_str(&read(&text(attempt, "report"))).unwrap();
                assert_eq!(validate_report(&report, &module), vec![], "{id}");
                assert_eq!(report.verdict.as_str(), text(attempt, "verdict"), "{id}");
                assert_eq!(module.target, text(attempt, "target"), "{id}");
                if let Some(shadow) = &report.shadow {
                    assert!(
                        shadow.path.starts_with(&shadow_root),
                        "{id}: {}",
                        shadow.path
                    );
                    assert_ne!(shadow.toolchain, "", "{id}: the toolchain is recorded");
                }
                for gap in &module.gaps {
                    assert!(
                        debts.contains_key(&gap.debt),
                        "{id}: {} owned by {}",
                        gap.subject,
                        gap.debt
                    );
                }
                reconstructed |= matches!(
                    report.verdict,
                    ReconstructionVerdict::ReconstructedEquivalent
                        | ReconstructionVerdict::ReconstructedWithDeclaredVariation
                );
            }
            // The latest attempt's gaps each feed a queued attack; a closed gap is gone from it.
            let latest: ConstructionModule =
                serde_json::from_str(&read(&text(attempts.last().unwrap(), "module"))).unwrap();
            let open: BTreeSet<&str> = latest.gaps.iter().map(|g| g.kind.as_str()).collect();
            for feedback in blocks(&ledger, "gap_feedback") {
                let gap = text(feedback, "gap");
                match text(feedback, "status").as_str() {
                    "OPEN" => {
                        assert!(
                            open.contains(gap.as_str()),
                            "{gap}: OPEN but not in the latest attempt"
                        );
                        assert!(
                            queued.contains(&text(feedback, "attack")),
                            "{gap}: its attack is not queued"
                        );
                    }
                    "CLOSED" => {
                        assert!(!open.contains(gap.as_str()), "{gap}: CLOSED but still open");
                        text(feedback, "closed_in");
                    }
                    // The attack is done and the re-attempt that shows it is pending: the gap may
                    // still be in the latest attempt, but once the named re-attempt exists it must
                    // not carry the gap.
                    "CLOSING" => {
                        let attack = text(feedback, "attack");
                        assert!(
                            debt_ledger.attack_ids().contains(&attack) && !queued.contains(&attack),
                            "{gap}: CLOSING needs its attack done"
                        );
                        let reattempt = text(feedback, "reattempt");
                        if let Some(done) = attempts.iter().find(|a| text(a, "id") == reattempt) {
                            let module: ConstructionModule =
                                serde_json::from_str(&read(&text(done, "module"))).unwrap();
                            assert!(
                                module.gaps.iter().all(|g| g.kind.as_str() != gap),
                                "{gap}: the re-attempt {reattempt} still has it"
                            );
                        }
                    }
                    other => panic!("{gap}: status {other}"),
                }
            }
            for gap in &open {
                assert!(
                    blocks(&ledger, "gap_feedback")
                        .iter()
                        .any(|f| text(f, "gap") == *gap
                            && ["OPEN", "CLOSING"].contains(&text(f, "status").as_str())),
                    "{gap}: an open gap without feedback"
                );
            }
            let reached = text(&ledger, "level_reached");
            if !reconstructed {
                assert_eq!(reached, "SH0", "no reconstruction, so no level above SH0");
            }
        }

        const REPLAY: &str = ".atlas/roadmap/FULL-OSS-REPLAY.toml";
        const REPLAY_TERMINAL: [&str; 10] = [
            "ABSORBED",
            "REFERENCE_ONLY",
            "REFERENCE_ONLY_UNTIL_TRIGGER",
            "EXTERNAL_BOUNDARY",
            "REVALIDATED",
            "REJECTED",
            "DUPLICATE_MECHANISM",
            "NOT_APPLICABLE",
            "BLOCKED_BY_LICENSE",
            "BLOCKED_BY_MISSING_CAPABILITY",
        ];

        /// `https://github.com/Owner/Repo.git` -> `owner/repo`; other hosts keep the host.
        fn replay_key(url: &str) -> String {
            let lower = url.trim().to_ascii_lowercase();
            let bare = lower
                .trim_start_matches("https://")
                .trim_start_matches("http://")
                .trim_end_matches('/')
                .trim_end_matches(".git")
                .to_owned();
            bare.strip_prefix("github.com/")
                .map_or(bare.clone(), str::to_owned)
        }

        fn is_pin(value: &str) -> bool {
            value.len() == 40 && value.chars().all(|c| c.is_ascii_hexdigit())
        }

        fn replay_ledger() -> (String, Vec<String>) {
            let text = read(REPLAY);
            let repositories = blocks(&text, "repository")
                .into_iter()
                .map(str::to_owned)
                .collect();
            (text, repositories)
        }

        fn replay_epochs(ledger: &str) -> Vec<String> {
            blocks(ledger, "epoch")
                .iter()
                .map(|e| text(e, "id"))
                .collect()
        }

        /// ADR 0067: a REPLAY generation's record in the replay ledger and its evidence.
        fn replay_generation_is_accounted(id: &str, block: &str) {
            let (ledger, repositories) = replay_ledger();
            let key = text(block, "replay");
            let record = repositories
                .iter()
                .find(|r| text(r, "key") == key)
                .unwrap_or_else(|| panic!("{id}: {key} is not in the replay ledger"));
            // The latest replay of the repository, or (G160) an earlier one its history names: a
            // revalidation replays a repository again.
            assert!(
                text(record, "replay_generation") == id
                    || list(record, "replays")
                        .iter()
                        .any(|r| r.split(' ').nth(1) == Some(id)),
                "{id}"
            );
            let pin = text(block, "pinned_commit");
            assert!(is_pin(&pin), "{id}: exact pin");
            assert_eq!(text(record, "pinned_commit"), pin, "{id}");
            // Deleted by this replay; a later replay may have materialized it again.
            assert!(
                !root().join(text(block, "source_path")).exists()
                    || text(record, "replay_status") == "MATERIALIZED",
                "{id}: the donor source must be deleted"
            );
            let epochs = replay_epochs(&ledger);
            for field in ["epoch_before", "epoch_after"] {
                assert!(epochs.contains(&text(block, field)), "{id}: {field}");
            }
            let evidence: serde_json::Value =
                serde_json::from_str(&read(&text(block, "mission"))).unwrap();
            for field in [
                "donor",
                "atlas_n_mission",
                "differential",
                "n_vs_n_plus_1",
                "manual_reads",
                "decision",
                "extinction",
            ] {
                assert!(
                    !evidence[field].is_null(),
                    "{id}: replay evidence lacks {field}"
                );
            }
            for field in ["atlas_knew", "challenge", "answer"] {
                assert!(
                    !evidence["atlas_n_mission"][field].is_null(),
                    "{id}: the Atlas_N mission lacks {field}"
                );
            }
            assert_eq!(evidence["extinction"]["path_absent_after"], true, "{id}");
        }

        /// ADR 0067: the replay ledger accounts for every repository any donor ledger names --
        /// the repo-exact frontier, the donor corpus, the First-50 campaign and the legacy
        /// unadmitted checkouts -- once, by canonical remote.
        #[test]
        fn full_oss_replay_accounts_every_canonical_donor_once() {
            let (ledger, repositories) = replay_ledger();
            let mut keys = BTreeSet::new();
            let mut names = BTreeSet::new();
            for record in &repositories {
                assert!(keys.insert(text(record, "key")), "duplicate replay key");
                names.extend(
                    list(record, "names")
                        .into_iter()
                        .map(|n| n.to_ascii_lowercase()),
                );
            }
            let mut required: Vec<(String, &str)> = Vec::new();
            for block in blocks(
                &read(".atlas/roadmap/RECOMMENDED-OSS-FRONTIER.toml"),
                "repository",
            ) {
                required.push((replay_key(&text(block, "canonical_url")), "frontier"));
            }
            for block in blocks(&read(".atlas/references/donor-corpus.toml"), "donor") {
                if let Some(url) = string(block, "resolved_url") {
                    required.push((replay_key(&url), "donor corpus"));
                }
            }
            for block in blocks(&read(".atlas/roadmap/FIRST-50-CAMPAIGN.toml"), "donor") {
                if let Some(url) = string(block, "canonical_url") {
                    required.push((replay_key(&url), "First-50"));
                }
            }
            for (key, source) in &required {
                assert!(
                    keys.contains(key),
                    "{source} repository {key} is not in the replay ledger"
                );
            }
            for block in blocks(
                &read(".atlas/roadmap/DONOR-WORKING-SET.toml"),
                "unadmitted_checkout",
            ) {
                let directory = text(block, "directory").to_ascii_lowercase();
                assert!(
                    names.contains(&directory) || keys.contains(&format!("name:{directory}")),
                    "legacy checkout {directory} is not in the replay ledger"
                );
            }
            let counts = table(&ledger, "counts");
            assert_eq!(number(counts, "total"), repositories.len() as i64);
            let status = |s: &str| {
                repositories
                    .iter()
                    .filter(|r| text(r, "replay_status") == s)
                    .count() as i64
            };
            assert_eq!(number(counts, "never_replayed"), status("NEVER_REPLAYED"));
            assert_eq!(number(counts, "materialized"), status("MATERIALIZED"));
            assert_eq!(number(counts, "queued"), status("QUEUED"));
            assert!(status("QUEUED") <= 1, "one donor is queued at a time");
            assert_eq!(number(counts, "processed"), status("PROCESSED"));
            assert_eq!(
                number(counts, "remaining"),
                repositories.len() as i64 - status("PROCESSED")
            );
            let processed: Vec<&String> = repositories
                .iter()
                .filter(|r| text(r, "replay_status") == "PROCESSED")
                .collect();
            let count = |field: &str, value: &str| {
                processed
                    .iter()
                    .filter(|r| string(r, field).as_deref() == Some(value))
                    .count() as i64
            };
            assert_eq!(
                number(counts, "capability_advanced"),
                count("capability_delta", "CAPABILITY_ADVANCED")
            );
            assert_eq!(
                number(counts, "no_capability_delta"),
                count("capability_delta", "NO_CAPABILITY_DELTA")
            );
            assert_eq!(
                number(counts, "revalidation_required"),
                count("trigger_status", "REVALIDATION_REQUIRED")
            );
            assert_eq!(
                number(counts, "source_extinct"),
                processed
                    .iter()
                    .filter(|r| flag(r, "source_extinct"))
                    .count() as i64
            );
        }

        /// ADR 0067: a processed replay has an exact pin, a terminal state valid at the epoch that
        /// decided it (never permanently), mission and N-versus-N+1 evidence when Atlas changed,
        /// no copied code from a restrictively licensed donor, and no source left behind; the
        /// one-donor window holds.
        #[test]
        fn every_replay_is_pinned_epoch_relative_and_extinct() {
            let (ledger, repositories) = replay_ledger();
            let epochs = replay_epochs(&ledger);
            assert!(!epochs.is_empty());
            for (index, epoch) in epochs.iter().enumerate() {
                assert_eq!(*epoch, format!("E{index}"), "epochs are E0, E1, ...");
            }
            let current = text(&ledger, "current_epoch");
            assert_eq!(epochs.last(), Some(&current));
            let generations: BTreeSet<String> =
                ledger_generations().into_iter().map(|(id, _)| id).collect();
            for epoch in blocks(&ledger, "epoch") {
                assert!(generations.contains(&text(epoch, "generation")), "{epoch}");
            }
            let next = text(&ledger, "next_replay");
            let mut materialized = Vec::new();
            for record in &repositories {
                let key = text(record, "key");
                let status = text(record, "replay_status");
                assert!(
                    ["NEVER_REPLAYED", "QUEUED", "MATERIALIZED", "PROCESSED"]
                        .contains(&status.as_str()),
                    "{key}: {status}"
                );
                if status == "MATERIALIZED" {
                    materialized.push(text(record, "source_path"));
                }
                if status != "PROCESSED" {
                    continue;
                }
                assert!(is_pin(&text(record, "pinned_commit")), "{key}: exact pin");
                assert!(
                    generations.contains(&text(record, "replay_generation")),
                    "{key}"
                );
                let terminal = text(record, "terminal_state");
                assert!(
                    REPLAY_TERMINAL.contains(&terminal.as_str()),
                    "{key}: {terminal}"
                );
                // A verdict is valid at its epoch: an older one is re-checked or re-opened.
                let decided = text(record, "decided_at_epoch");
                assert!(epochs.contains(&decided), "{key}");
                let trigger = text(record, "trigger_status");
                assert!(
                    ["CURRENT", "REVALIDATION_REQUIRED"].contains(&trigger.as_str()),
                    "{key}"
                );
                if decided != current && trigger == "CURRENT" {
                    assert_eq!(text(record, "trigger_checked_at_epoch"), current, "{key}");
                }
                text(record, "revalidation_trigger");
                // Mission evidence; an epoch change carries the N versus N+1 comparison.
                assert!(root().join(text(record, "mission")).exists(), "{key}");
                let before = text(record, "epoch_before");
                let after = text(record, "epoch_after");
                match text(record, "capability_delta").as_str() {
                    "CAPABILITY_ADVANCED" => {
                        assert_ne!(before, after, "{key}: an advance moves the epoch");
                        let delta: serde_json::Value =
                            serde_json::from_str(&read(&text(record, "n_plus_1"))).unwrap();
                        assert!(!delta["n_vs_n_plus_1"].is_null(), "{key}: N versus N+1");
                    }
                    "NO_CAPABILITY_DELTA" => assert_eq!(before, after, "{key}"),
                    other => panic!("{key}: capability_delta {other}"),
                }
                // A donor decision never closes capability debt by itself.
                assert!(raw(record, "closes_debt").is_none(), "{key}");
                // A restrictively licensed donor is studied, never copied.
                let license = text(record, "license").to_ascii_lowercase();
                if license.contains("noncommercial") || license.contains("polyform") {
                    assert_eq!(text(record, "code_reuse"), "NONE", "{key}");
                }
                assert!(flag(record, "source_extinct"), "{key}: source left behind");
                assert!(
                    !root().join(text(record, "source_path")).exists(),
                    "{key}: source path still exists"
                );
                // A processed repository is replayed again only when its verdict was reopened.
                if key == next {
                    assert_eq!(
                        trigger, "REVALIDATION_REQUIRED",
                        "{key}: replayed again while CURRENT"
                    );
                }
            }
            let queued = repositories
                .iter()
                .find(|r| text(r, "key") == next)
                .unwrap_or_else(|| panic!("next_replay {next} is not in the ledger"));
            // The selected next donor is QUEUED, or a processed one whose verdict was re-opened.
            match text(queued, "replay_status").as_str() {
                "QUEUED" => {}
                "PROCESSED" => assert_eq!(text(queued, "trigger_status"), "REVALIDATION_REQUIRED"),
                other => panic!("next_replay {next} is {other}"),
            }
            // One donor at a time, and only the materialized one on disk.
            let window = number(&ledger, "max_materialized") as usize;
            assert!(materialized.len() <= window);
            let cache = root().join(text(&ledger, "materialization_root"));
            if cache.is_dir() {
                for entry in std::fs::read_dir(&cache).unwrap() {
                    let path = entry.unwrap().path();
                    let relative = path
                        .strip_prefix(root())
                        .unwrap()
                        .to_string_lossy()
                        .into_owned();
                    assert!(
                        materialized.contains(&relative),
                        "{relative} is on disk but no replay is MATERIALIZED there"
                    );
                }
            }
        }

        /// ADR 0067: from the campaign start, no more than `max_non_replay_between` generations
        /// pass without a REPLAY, unless a generation names the materialized donor it serves as
        /// a prerequisite.
        #[test]
        fn replay_cadence_is_machine_enforced() {
            let (ledger, _) = replay_ledger();
            let start = generation(&text(&ledger, "campaign_start"));
            let allowed = number(&ledger, "max_non_replay_between");
            let mut run = 0;
            let mut replays = 0;
            for (id, block) in ledger_generations() {
                if generation(&id) < start {
                    continue;
                }
                if text(&block, "kind") == "REPLAY" {
                    run = 0;
                    replays += 1;
                } else if string(&block, "replay_prerequisite").is_none() {
                    run += 1;
                    assert!(
                        run <= allowed,
                        "{id}: more than {allowed} non-replay generations without a replay"
                    );
                }
            }
            if current_generation() >= start {
                assert!(replays > 0, "the campaign start generation is a replay");
            }
            // The plan keeps the cadence: after a non-replay generation, the next is a replay.
            if run >= allowed {
                let priority = read(".atlas/roadmap/PRIORITY.toml");
                let next = format!("G{}", current_generation() + 1);
                assert!(
                    blocks(&priority, "planned_generation").iter().any(|b| {
                        string(b, "id") == Some(next.clone())
                            && string(b, "objective")
                                .is_some_and(|o| o.starts_with("FULL_OSS_REPLAY"))
                    }),
                    "{next} must be planned as a FULL_OSS_REPLAY generation"
                );
            }
        }

        #[test]
        fn audit_completion_requires_a_proven_native_attack() {
            let gate = read(GATE);
            let audit = table(&gate, "audit");
            let ledger = Ledger::load();
            let status = text(audit, "status");
            let selected = text(audit, "selected_attack");
            assert!(ledger.attack_ids().contains(&selected), "{selected}");
            match status.as_str() {
                "NATIVE_ATTACK_PENDING" => {
                    let head = blocks(&ledger.text, "native_attack")[0];
                    assert_eq!(
                        text(head, "id"),
                        selected,
                        "the selected attack heads the queue"
                    );
                }
                "COMPLETE" => {
                    let generation_id = text(audit, "native_attack_generation");
                    let (_, block) = ledger_generations()
                        .into_iter()
                        .find(|(id, _)| *id == generation_id)
                        .unwrap_or_else(|| panic!("{generation_id} not in the ledger"));
                    assert_eq!(text(&block, "kind"), "NATIVE_ATTACK");
                    assert!(
                        blocks(&ledger.text, "native_attack_done")
                            .iter()
                            .any(|b| text(b, "generation") == generation_id
                                && text(b, "id") == selected),
                        "the completed attack is recorded as done in {generation_id}"
                    );
                    // generation_ledger_self_recensus_chain proves every ledger generation.
                    text(&block, "self_recensus");
                }
                other => panic!("audit status {other}"),
            }
            // While pending, the pressure map's selection is the attack the audit must run; once
            // complete, the map has moved on to the next selection.
            if status == "NATIVE_ATTACK_PENDING" {
                let pressure = read(PRESSURE);
                assert_eq!(
                    text(table(&pressure, "selection"), "selected_attack"),
                    selected
                );
            }
        }

        #[test]
        fn pressure_map_restates_the_ledger() {
            let ledger = Ledger::load();
            let debts = ledger.debts();
            let pressure = read(PRESSURE);
            let mut seen = BTreeSet::new();
            let mut previous = i64::MAX;
            for (index, block) in blocks(&pressure, "pressure").iter().enumerate() {
                assert_eq!(number(block, "rank"), index as i64 + 1);
                let id = text(block, "debt");
                let debt = debts.get(&id).unwrap_or_else(|| panic!("{id}"));
                for (map_field, ledger_field) in [
                    ("current_maturity", "current_maturity"),
                    ("required_maturity", "required_maturity"),
                    ("next_attack", "next_attack"),
                    ("blocking_gate", "deadline_gate"),
                    ("escalation_state", "escalation_state"),
                ] {
                    assert_eq!(
                        text(block, map_field),
                        text(debt, ledger_field),
                        "{id}: {map_field}"
                    );
                }
                assert_eq!(
                    number(block, "debt_age"),
                    number(debt, "stale_generations"),
                    "{id}"
                );
                assert_eq!(
                    list(block, "dependencies"),
                    list(debt, "blocked_by"),
                    "{id}"
                );
                assert_eq!(
                    list(block, "donors_tried"),
                    list(debt, "donors_examined"),
                    "{id}"
                );
                let score = number(block, "pressure");
                assert!(score <= previous, "pressure ranks descend");
                previous = score;
                seen.insert(id);
            }
            let open: BTreeSet<String> = debts
                .iter()
                .filter(|(_, b)| text(b, "current_state") != "CLOSED")
                .map(|(id, _)| id.clone())
                .collect();
            assert_eq!(seen, open, "every non-closed debt is on the pressure map");
        }

        #[test]
        fn donor_clusters_expose_unattacked_essential_capabilities() {
            let audit = read(AUDIT);
            let ledger = Ledger::load();
            let known = ledger.known_ids();
            let debts = ledger.debts();
            let queued = ledger.queued();
            let all = donors();
            let mut placed = BTreeSet::new();
            for cluster in blocks(&audit, "donor_cluster") {
                let id = text(cluster, "id");
                let class = text(cluster, "class");
                let members = list(cluster, "donors");
                let absorbed = members
                    .iter()
                    .filter(|m| {
                        all.iter().any(|d| {
                            &d.name == *m && text(&d.block, "mechanism_decision") == "ABSORBED"
                        })
                    })
                    .count() as i64;
                assert_eq!(number(cluster, "donor_count"), members.len() as i64, "{id}");
                assert_eq!(number(cluster, "absorbed_count"), absorbed, "{id}");
                assert_eq!(
                    flag(cluster, "hole"),
                    class == "ESSENTIAL" && absorbed == 0,
                    "{id}"
                );
                for member in &members {
                    assert!(placed.insert(member.clone()), "{member} in two clusters");
                    let donor = all
                        .iter()
                        .find(|d| &d.name == member)
                        .expect("audited donor");
                    assert_eq!(text(&donor.block, "capability_cluster"), id, "{member}");
                }
                let routed = list(cluster, "debts");
                assert_eq!(class == "OPTIONAL", routed.is_empty(), "{id}");
                for debt in &routed {
                    assert!(known.contains(debt), "{id}: {debt}");
                }
                // A hole (no donor absorbed) is priority debt: each essential debt it names is
                // planned -- queued, or blocked by a queued debt, or frozen.
                if flag(cluster, "hole") {
                    for debt in routed.iter().filter(|d| d.starts_with("DEBT-")) {
                        let block = debts[debt.as_str()];
                        assert!(
                            queued.contains_key(debt)
                                || list(block, "blocked_by")
                                    .iter()
                                    .any(|b| queued.contains_key(b))
                                || flag(block, "frozen"),
                            "{id}: hole debt {debt} has no planned attack"
                        );
                    }
                }
            }
            assert_eq!(
                placed.len(),
                all.len(),
                "every donor sits in exactly one cluster"
            );
        }

        #[test]
        fn semantic_dimensions_and_avoidance_drift_are_audited() {
            let ledger = Ledger::load();
            let debts = ledger.debts();
            let dimensions: Vec<String> = blocks(&ledger.text, "dimension")
                .into_iter()
                .map(|b| {
                    let id = text(b, "id");
                    let debt = text(b, "debt");
                    let owner = debts.get(&debt).unwrap_or_else(|| panic!("{id}: {debt}"));
                    for field in [
                        "resolution_quality",
                        "oracle",
                        "known_blind_spots",
                        "closure_requirement",
                    ] {
                        text(b, field);
                    }
                    for field in [
                        "independent_engines",
                        "unknown_count",
                        "unsupported_count",
                        "conflict_count",
                    ] {
                        assert!(number(b, field) >= 0);
                    }
                    assert_eq!(
                        list(b, "native_engines").len() as i64,
                        number(b, "independent_engines"),
                        "{id}"
                    );
                    // An incomplete essential dimension stays OPEN whatever its donors became.
                    if text(b, "debt_class") == "ESSENTIAL" && text(b, "coverage") != "OBSERVED" {
                        assert_ne!(text(owner, "current_state"), "CLOSED", "{id}");
                    }
                    id
                })
                .collect();
            // G120: counts of census dimensions are derived from the head post-change snapshot.
            let head = format!("G{}", current_generation());
            let post: serde_json::Value =
                serde_json::from_str(&read(&format!(".atlas/evidence/census/{head}/post.json")))
                    .unwrap();
            let totals = post["totals"].as_object().unwrap();
            for block in blocks(&ledger.text, "dimension") {
                let id = text(block, "id");
                let prefix = format!("obligations:{id}|");
                if !totals.keys().any(|k| k.starts_with(&prefix)) {
                    continue;
                }
                for (field, status) in [
                    ("unknown_count", "|UNKNOWN"),
                    ("unsupported_count", "|UNSUPPORTED"),
                ] {
                    let derived: i64 = totals
                        .iter()
                        .filter(|(k, _)| k.starts_with(&prefix) && k.ends_with(status))
                        .map(|(_, v)| v.as_i64().unwrap())
                        .sum();
                    assert_eq!(
                        number(block, field),
                        derived,
                        "{id}: {field} from {head} post.json"
                    );
                }
            }
            let expected = [
                "SYMBOL",
                "TYPE",
                "CALL",
                "CONTROL_FLOW",
                "DATA_FLOW",
                "STATE",
                "EFFECT",
                "OWNERSHIP",
                "RESOURCE",
                "CONCURRENCY",
                "PERSISTENCE",
                "DEPENDENCY",
                "PROVENANCE",
                "UNCERTAINTY",
                "CAUSALITY",
            ];
            assert_eq!(
                dimensions, expected,
                "the fifteen fundamental dimensions, in order"
            );
            let drift: Vec<&str> = blocks(&ledger.text, "avoidance_drift");
            for block in &drift {
                assert_eq!(text(block, "proved"), "NOT_NEEDED_NOW");
                let treated = text(block, "treated_as");
                assert_eq!(
                    flag(block, "drift"),
                    treated == "NOT_ARCHITECTURALLY_REQUIRED"
                );
                for debt in list(block, "debts") {
                    assert!(ledger.known_ids().contains(&debt), "{debt}");
                }
                text(block, "correction");
            }
            for donor in donors() {
                if flag(&donor.block, "conflated") {
                    assert!(
                        drift
                            .iter()
                            .any(|b| text(b, "source") == donor.name && flag(b, "drift")),
                        "{}: conflated decision without a drift record",
                        donor.name
                    );
                }
            }
            let epistemic: Vec<String> = blocks(&ledger.text, "epistemic_state")
                .into_iter()
                .map(|b| text(b, "id"))
                .collect();
            assert_eq!(
                epistemic,
                [
                    "OBSERVED",
                    "DECLARED",
                    "DERIVED",
                    "SIMULATED",
                    "PREDICTED",
                    "HYPOTHESIZED",
                    "COUNTERFACTUAL",
                    "FALSIFIED",
                    "VALIDATED"
                ]
            );
            for table_name in ["physical_primitive", "chronica_blocker"] {
                for block in blocks(&ledger.text, table_name) {
                    let named = string(block, "debt")
                        .map(|d| vec![d])
                        .unwrap_or_else(|| list(block, "debts"));
                    for debt in named {
                        assert!(
                            debts.contains_key(&debt),
                            "{table_name}: unknown debt {debt}"
                        );
                    }
                }
            }
        }

        #[test]
        fn every_frontier_family_routes_to_a_capability_cluster() {
            let known = Ledger::load().known_ids();
            let clusters = read(".atlas/roadmap/FRONTIER-CAPABILITY-CLUSTERS.toml");
            let mut family_cluster = BTreeMap::new();
            let mut cluster_ids = BTreeSet::new();
            for block in blocks(&clusters, "cluster") {
                let id = text(block, "id");
                assert!(cluster_ids.insert(id.clone()), "{id} twice");
                let class = text(block, "class");
                let routed = list(block, "debts");
                assert!(
                    ["ESSENTIAL", "SCALE_TRIGGERED", "OPTIONAL"].contains(&class.as_str()),
                    "{id}: {class}"
                );
                assert_eq!(
                    class == "OPTIONAL",
                    routed.is_empty(),
                    "{id}: OPTIONAL iff no debt"
                );
                for debt in routed {
                    assert!(known.contains(&debt), "{id}: unknown debt {debt}");
                }
                for family in list(block, "families") {
                    assert!(
                        family_cluster.insert(family.clone(), id.clone()).is_none(),
                        "{family} in two clusters"
                    );
                }
            }
            let unfamilied: BTreeMap<String, String> = blocks(&clusters, "unfamilied")
                .into_iter()
                .map(|block| (text(block, "name"), text(block, "cluster")))
                .collect();
            let frontier = read(".atlas/roadmap/RECOMMENDED-OSS-FRONTIER.toml");
            let mut used = BTreeSet::new();
            for block in blocks(&frontier, "repository") {
                let families = list(block, "families");
                if families.is_empty() {
                    let names = list(block, "names");
                    let cluster = names
                        .iter()
                        .find_map(|n| unfamilied.get(n))
                        .unwrap_or_else(|| panic!("{names:?}: no family and no cluster"));
                    assert!(cluster_ids.contains(cluster), "{cluster}");
                }
                for family in families {
                    assert!(
                        family_cluster.contains_key(&family),
                        "frontier family `{family}` routes to no capability cluster"
                    );
                    used.insert(family);
                }
            }
            let stale: Vec<_> = family_cluster
                .keys()
                .filter(|f| !used.contains(*f))
                .collect();
            assert!(
                stale.is_empty(),
                "clustered families not in the frontier: {stale:?}"
            );
        }

        #[test]
        fn every_end_state_capability_is_owned_by_debt_or_closed() {
            let ledger = Ledger::load();
            let known = ledger.known_ids();
            let end_state = read(".atlas/roadmap/FUTURISM-ENGINEERING-END-STATE.toml");
            let capabilities = blocks(&end_state, "capability");
            assert_eq!(capabilities.len(), 18, "the 18 end-state capabilities");
            let mut ids = BTreeSet::new();
            for block in capabilities {
                let id = text(block, "id");
                let owned = list(block, "debts");
                let native = text(block, "native_state");
                assert!(
                    !owned.is_empty() || native.starts_with("CLOSED"),
                    "{id}: neither owned by a debt nor closed"
                );
                for debt in owned {
                    assert!(known.contains(&debt), "{id}: unknown debt {debt}");
                }
                ids.insert(id);
            }
            let verbs: Vec<String> = blocks(&end_state, "verb")
                .into_iter()
                .map(|b| {
                    for capability in list(b, "capabilities") {
                        assert!(
                            ids.contains(&capability),
                            "verb routes to unknown {capability}"
                        );
                    }
                    text(b, "id")
                })
                .collect();
            assert_eq!(
                verbs,
                [
                    "understand",
                    "represent",
                    "reason",
                    "derive",
                    "constrain",
                    "search",
                    "compare",
                    "select",
                    "simulate",
                    "predict",
                    "construct",
                    "compile",
                    "fabricate",
                    "execute",
                    "observe",
                    "measure",
                    "falsify",
                    "verify",
                    "recensus",
                    "evolve"
                ]
            );
            let domains = blocks(&end_state, "domain");
            assert_eq!(domains.len(), 17, "the 17 end-state domains");
            for block in domains {
                let id = text(block, "id");
                let state = text(block, "state");
                assert!(
                    ["NOW", "FROZEN", "CONTRACT", "ABSENT"].contains(&state.as_str()),
                    "{id}: {state}"
                );
                for debt in list(block, "core_debts") {
                    assert!(known.contains(&debt), "{id}: unknown debt {debt}");
                }
            }
        }

        #[test]
        fn construction_graph_is_finite_and_owned() {
            let ledger = Ledger::load();
            let debts = ledger.debts();
            let mut nodes: BTreeMap<String, (String, Vec<String>)> = BTreeMap::new();
            for block in blocks(&ledger.text, "construction_node") {
                let id = text(block, "id");
                let status = text(block, "status");
                if status == "MISSING" {
                    let debt = text(block, "debt");
                    let owner = debts
                        .get(&debt)
                        .unwrap_or_else(|| panic!("{id}: unknown debt {debt}"));
                    assert_ne!(
                        text(owner, "current_state"),
                        "CLOSED",
                        "{id}: {debt} closed"
                    );
                } else {
                    assert_eq!(status, "EXISTS", "{id}");
                }
                let previous = nodes.insert(id.clone(), (status, list(block, "requires")));
                assert!(previous.is_none(), "{id} twice");
            }
            for (id, (status, requires)) in &nodes {
                for required in requires {
                    let (required_status, _) = nodes
                        .get(required)
                        .unwrap_or_else(|| panic!("{id} requires unknown {required}"));
                    if status == "EXISTS" {
                        assert_eq!(required_status, "EXISTS", "{id} exists before {required}");
                    }
                }
            }
            // Acyclic: repeatedly retire nodes whose requirements are all retired.
            let mut done = BTreeSet::new();
            while done.len() < nodes.len() {
                let ready: Vec<_> = nodes
                    .iter()
                    .filter(|(id, (_, req))| {
                        !done.contains(*id) && req.iter().all(|r| done.contains(r))
                    })
                    .map(|(id, _)| id.clone())
                    .collect();
                assert!(!ready.is_empty(), "construction graph has a cycle");
                done.extend(ready);
            }
            for milestone in ["MIN_ATLASX", "FIRST_ARTIFACT"] {
                assert!(nodes.contains_key(milestone), "{milestone} missing");
            }
        }

        /// G145: dependency order includes the construction graph. The queue head's primary debt,
        /// when it owns construction nodes, owns one whose requirements all EXIST -- NA-FIRST-ARTIFACT
        /// was planned for G145 while its M17 sat behind ten missing nodes.
        #[test]
        fn the_queue_head_is_construction_reachable() {
            let ledger = Ledger::load();
            let nodes = blocks(&ledger.text, "construction_node");
            let status: BTreeMap<String, String> = nodes
                .iter()
                .map(|block| (text(block, "id"), text(block, "status")))
                .collect();
            let head = blocks(&ledger.text, "native_attack")[0];
            let primary = list(head, "debts")[0].clone();
            let frontier: Vec<bool> = nodes
                .iter()
                .filter(|block| {
                    text(block, "status") == "MISSING" && text(block, "debt") == primary
                })
                .map(|block| {
                    list(block, "requires")
                        .iter()
                        .all(|r| status[r] == "EXISTS")
                })
                .collect();
            assert!(
                frontier.is_empty() || frontier.contains(&true),
                "{}: {primary} owns no construction node whose requirements exist",
                text(head, "id")
            );
        }
    }

    /// `.atlas/scripts/verify-donor-quarantine.sh` enforces `.atlas/contracts/
    /// DONOR-WORKBENCH-ISOLATION.md`'s invariant (no live agent-tooling-shaped path under donors).
    /// A delegated contract-vs-code cross-check found it used `find -type d`/`-type f`, which
    /// classify a symlink by its OWN type, never by what it resolves to -- so a `.claude`/
    /// `CLAUDE.md`-named SYMLINK to a real directory/file was invisible to every check, even though
    /// it is exactly as live and discoverable as a literal one. This module runs the real script
    /// (accepting an overridable donors-root argument added specifically for this test) against a
    /// scratch fixture, never against this repository's own real donor corpus, so it is a genuine
    /// permanent regression test rather than a one-off manual verification.
    #[cfg(unix)]
    mod donor_quarantine_script_symlink_detection {
        use std::{fs, os::unix::fs::symlink, path::PathBuf, process::Command};

        fn workspace_root() -> PathBuf {
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .canonicalize()
                .expect("workspace root must exist")
        }

        fn scratch_dir(name: &str) -> PathBuf {
            std::env::temp_dir().join(format!(
                "atlas-donor-quarantine-test-{name}-{}",
                std::process::id()
            ))
        }

        fn run_quarantine_script(donors_root: &std::path::Path) -> std::process::Output {
            Command::new(workspace_root().join(".atlas/scripts/verify-donor-quarantine.sh"))
                .arg(donors_root)
                .output()
                .expect("verify-donor-quarantine.sh must be runnable")
        }

        #[test]
        fn a_symlinked_dot_claude_directory_is_detected_not_silently_missed() {
            let dir = scratch_dir("symlinked-dir");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("some-donor/real-target")).unwrap();
            symlink(
                dir.join("some-donor/real-target"),
                dir.join("some-donor/.claude"),
            )
            .unwrap();

            let output = run_quarantine_script(&dir);
            assert!(
                !output.status.success(),
                "a .claude directory that is a symlink to a real directory must be flagged, not \
                 silently treated as clean"
            );

            fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_symlinked_claude_md_file_is_detected_not_silently_missed() {
            let dir = scratch_dir("symlinked-file");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("some-donor")).unwrap();
            fs::write(dir.join("some-donor/real-instructions.md"), "content\n").unwrap();
            symlink(
                dir.join("some-donor/real-instructions.md"),
                dir.join("some-donor/CLAUDE.md"),
            )
            .unwrap();

            let output = run_quarantine_script(&dir);
            assert!(
                !output.status.success(),
                "a CLAUDE.md that is a symlink to a real file must be flagged, not silently \
                 treated as clean"
            );

            fs::remove_dir_all(&dir).unwrap();
        }

        #[test]
        fn a_donor_tree_with_no_quarantine_violations_still_scans_clean() {
            let dir = scratch_dir("clean");
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(dir.join("some-donor/src")).unwrap();
            fs::write(dir.join("some-donor/src/lib.rs"), "fn main() {}\n").unwrap();

            let output = run_quarantine_script(&dir);
            assert!(
                output.status.success(),
                "an ordinary donor tree with no agent-tooling-shaped paths must scan clean: {:?}",
                String::from_utf8_lossy(&output.stdout)
            );

            fs::remove_dir_all(&dir).unwrap();
        }
    }

    fn constraint_result(name: &str, passed: bool) -> ConstraintResult {
        verdict_result(
            name,
            if passed {
                ConstraintVerdict::Satisfied
            } else {
                ConstraintVerdict::Violated
            },
        )
    }

    fn verdict_result(name: &str, verdict: ConstraintVerdict) -> ConstraintResult {
        ConstraintResult {
            name: name.into(),
            passed: verdict.admits(),
            verdict,
            diagnostics: Vec::new(),
            derivation: Vec::new(),
        }
    }

    #[test]
    fn an_unknown_constraint_blocks_under_its_own_label_never_as_a_violation_or_a_pass() {
        let results = [
            verdict_result("A", ConstraintVerdict::Satisfied),
            verdict_result("Undecidable", ConstraintVerdict::Unknown),
        ];
        assert!(adl_constraint_unknown_blocks(&results));
        assert!(!adl_constraint_violation_blocks(&results));
        let violated = [verdict_result("B", ConstraintVerdict::Violated)];
        assert!(!adl_constraint_unknown_blocks(&violated));
        assert!(adl_constraint_violation_blocks(&violated));
    }

    #[test]
    fn no_constraint_results_never_blocks() {
        assert!(!adl_constraint_violation_blocks(&[]));
    }

    #[test]
    fn all_passing_constraint_results_never_block() {
        assert!(!adl_constraint_violation_blocks(&[
            constraint_result("A", true),
            constraint_result("B", true),
        ]));
    }

    #[test]
    fn a_single_failing_constraint_result_blocks() {
        // This is the exact defect this helper replaces: a declared constraint, invariant, or
        // materialization delta failing (passed: false) previously had no effect on
        // coding_admission at all, since only `adl.diagnostics` was inspected.
        assert!(adl_constraint_violation_blocks(&[
            constraint_result("A", true),
            constraint_result("ObservedMaterialization:WebUI", false),
        ]));
    }

    /// G63 (ADR 0026): the committed census-derived ADL equals what the current census derives
    /// -- a new or removed workspace dependency fails here until `adl derive` is re-run and the
    /// change is declared in the generation's self-recensus intent.
    #[test]
    fn integrity_envelope_is_pinned_and_atlas_is_eligible() {
        let _census = crate::whole_repo_census_lock();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let pinned = integrity::read_envelope(root.join(integrity::PINNED_ENVELOPE_PATH)).unwrap();
        assert_eq!(
            pinned,
            integrity::envelope(&root).unwrap(),
            "re-pin with `atlas-systemizer integrity envelope --out {}`",
            integrity::PINNED_ENVELOPE_PATH
        );
        let report = integrity::report(&root, &pinned).unwrap();
        assert_eq!(
            report.verdict,
            integrity::IntegrityVerdict::Eligible,
            "{report:#?}"
        );
        assert!(integrity::check_report(&report, &pinned).is_empty());
        // Both records conform to their JSON schemas.
        for (value, schema) in [
            (
                serde_json::to_value(&pinned).unwrap(),
                "architectural-integrity-envelope",
            ),
            (
                serde_json::to_value(&report).unwrap(),
                "architectural-integrity-report",
            ),
        ] {
            let schema: serde_json::Value = serde_json::from_str(
                &std::fs::read_to_string(root.join(format!(".atlas/schemas/{schema}.schema.json")))
                    .unwrap(),
            )
            .unwrap();
            let problems = conformance(&schema, &schema, &value, "$");
            assert!(problems.is_empty(), "{problems:#?}");
        }
    }

    /// The JSON-schema subset the integrity schemas use: `$ref` into `$defs`, object `required`,
    /// `properties` and `additionalProperties: false`, array `items` and `minItems`, `enum`,
    /// string `minLength`, and `type` (a name or a list of names).
    fn conformance(
        root: &serde_json::Value,
        schema: &serde_json::Value,
        value: &serde_json::Value,
        at: &str,
    ) -> Vec<String> {
        use serde_json::Value;
        if let Some(reference) = schema["$ref"].as_str() {
            let name = reference.trim_start_matches("#/$defs/");
            return conformance(root, &root["$defs"][name], value, at);
        }
        let mut problems = Vec::new();
        let type_of = |v: &Value| match v {
            Value::Null => "null",
            Value::Bool(_) => "boolean",
            Value::Number(n) if n.is_u64() || n.is_i64() => "integer",
            Value::Number(_) => "number",
            Value::String(_) => "string",
            Value::Array(_) => "array",
            Value::Object(_) => "object",
        };
        let allowed: Vec<&str> = match &schema["type"] {
            Value::String(t) => vec![t.as_str()],
            Value::Array(ts) => ts.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !allowed.is_empty() && !allowed.contains(&type_of(value)) {
            problems.push(format!("{at}: {} is not {allowed:?}", type_of(value)));
            return problems;
        }
        if let Some(options) = schema["enum"].as_array()
            && !options.contains(value)
        {
            problems.push(format!("{at}: {value} is not one of {options:?}"));
        }
        if let (Some(min), Some(text)) = (schema["minLength"].as_u64(), value.as_str())
            && (text.len() as u64) < min
        {
            problems.push(format!("{at}: shorter than {min}"));
        }
        if let Some(items) = value.as_array() {
            if let Some(min) = schema["minItems"].as_u64()
                && (items.len() as u64) < min
            {
                problems.push(format!("{at}: fewer than {min} items"));
            }
            for (i, item) in items.iter().enumerate() {
                problems.extend(conformance(
                    root,
                    &schema["items"],
                    item,
                    &format!("{at}[{i}]"),
                ));
            }
        }
        if let Some(object) = value.as_object() {
            for required in schema["required"].as_array().into_iter().flatten() {
                let key = required.as_str().unwrap();
                if !object.contains_key(key) {
                    problems.push(format!("{at}: missing `{key}`"));
                }
            }
            for (key, field) in object {
                match schema["properties"].get(key) {
                    Some(property) => {
                        problems.extend(conformance(root, property, field, &format!("{at}.{key}")))
                    }
                    None if schema["additionalProperties"] == Value::Bool(false) => {
                        problems.push(format!("{at}: `{key}` is not allowed"))
                    }
                    None => {}
                }
            }
        }
        problems
    }

    #[test]
    fn census_adl_is_current() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let committed = std::fs::read_to_string(root.join(CENSUS_ADL_PATH)).unwrap();
        assert_eq!(
            committed,
            derive_census_adl(&root).unwrap(),
            "regenerate with `atlas-systemizer adl derive --out {CENSUS_ADL_PATH}`"
        );
    }

    /// Every entry point reconciles the authored ADL against the dependency census: on this
    /// repository every observed member dependency is declared and SATISFIED, and the declared
    /// WebUI -> Runtime (not a Cargo member) is accounted as not censusable, never passed.
    #[test]
    fn systemize_reconciles_declared_dependencies_against_the_census() {
        let _census = crate::whole_repo_census_lock();
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let report = systemize(&root).unwrap();
        let reconciled: Vec<(&str, atlas_core::ConstraintVerdict)> = report
            .adl
            .constraint_results
            .iter()
            .filter(|c| {
                c.derivation.first().map(|d| d.rule)
                    == Some(atlas_core::language::adl::ConstraintCheckKind::ObservedDependency)
            })
            .map(|c| (c.name.as_str(), c.verdict))
            .collect();
        let satisfied = atlas_core::ConstraintVerdict::Satisfied;
        assert_eq!(
            reconciled,
            [
                ("DeclaredDependency:Adapter->Core", satisfied),
                ("DeclaredDependency:AtlasCli->Runtime", satisfied),
                ("DeclaredDependency:Runtime->Adapter", satisfied),
                ("DeclaredDependency:Runtime->Core", satisfied),
            ]
        );
        assert!(report.adl.deltas.iter().any(
            |d| d.code == "DECLARED_DEPENDENCY_NOT_CENSUSABLE" && d.subject == "WebUI->Runtime"
        ));
        assert!(
            report.coding_admission.allowed,
            "{:?}",
            report.coding_admission.blockers
        );

        // The self-recensus snapshot attributes every ADL fact to its ADL source (v2): nothing is
        // unattributed, and census.adl is a tracked ADL source of its own.
        let snapshot = atlas_core::recensus::CensusSnapshot::from_report(&report);
        assert_eq!(snapshot.totals.get("unattributed_semantics"), Some(&0));
        assert!(snapshot.totals.get("adl_semantics").is_some_and(|n| *n > 0));
        assert!(snapshot.adl.sources.contains_key(CENSUS_ADL_PATH));
        assert!(
            snapshot
                .adl
                .sources
                .contains_key(".atlas/declared/system.adl")
        );

        // G66: every function has a revision-stable descriptor, and descriptors never collide
        // across files (the span-free key had 39 cross-file collisions); a duplicate can only be
        // same-file alternatives, which correspondence reports as AMBIGUOUS.
        let signatures = report
            .census
            .typed_semantic_records
            .iter()
            .filter(|r| matches!(r, atlas_core::SemanticObservation::FunctionSignature(_)))
            .count();
        assert_eq!(snapshot.entities.len(), signatures);
        let mut files: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
            Default::default();
        for e in &snapshot.entities {
            files.entry(&e.descriptor).or_default().insert(&e.path);
        }
        let cross_file: Vec<_> = files.iter().filter(|(_, paths)| paths.len() > 1).collect();
        assert!(cross_file.is_empty(), "{cross_file:?}");
        assert!(
            snapshot
                .entities
                .iter()
                .all(|e| e.body.starts_with("blake3-256:") || e.body == "-")
        );

        // G67: no symbol or file-scoped type identity spans two source artifacts (203 did at
        // G66). A canonical type (G83) is one type everywhere, so its claim is shared by design.
        let mut spans: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
            Default::default();
        let mut canonical: std::collections::BTreeMap<&str, std::collections::BTreeSet<&str>> =
            Default::default();
        for record in &report.census.typed_semantic_records {
            if let atlas_core::SemanticObservation::Symbol(h) = record {
                spans
                    .entry(h.record_id.as_str())
                    .or_default()
                    .insert(&h.provenance.source_path);
            }
            if let atlas_core::SemanticObservation::Type(h) = record {
                let entry = if h.subject.canonical.is_some() {
                    &mut canonical
                } else {
                    &mut spans
                };
                entry
                    .entry(h.record_id.as_str())
                    .or_default()
                    .insert(&h.provenance.source_path);
            }
        }
        let shared: Vec<_> = spans.iter().filter(|(_, files)| files.len() > 1).collect();
        assert!(
            shared.is_empty(),
            "{} ids span files: {shared:?}",
            shared.len()
        );
        assert!(
            canonical.values().any(|files| files.len() > 1),
            "canonical type claims are shared across files"
        );
    }

    /// Only a CLOSED dependency census is authoritative for reconciliation.
    #[test]
    fn an_unclosed_dependency_census_is_never_reconciled_against() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let mut closure = resolve_dependency_closure(&root).unwrap();
        let source = atlas_core::SourceReport {
            schema: "test".into(),
            root: "/repo".into(),
            files_total: 0,
            languages: Default::default(),
            files: Vec::new(),
        };
        let authored = [atlas_core::AdlSource {
            path: ".atlas/declared/system.adl".into(),
            text: "atlas 1\nsystem T\nentity Runtime A {}\nentity Runtime B {}\n\
                   A ->depends_on-> B\nmaterialize A {\n    path = \"core\"\n}\n\
                   materialize B {\n    path = \"runtime\"\n}\n"
                .into(),
        }];
        let mut adl = compile_adl(&authored, &source);
        let before = adl.constraint_results.len();
        reconcile_adl_with_dependency_census(&mut adl, &closure);
        assert!(
            adl.constraint_results
                .iter()
                .any(|c| c.name == "DeclaredDependency:A->B" && !c.passed),
            "core does not depend on runtime"
        );
        closure.state = DependencyClosureState::Partial;
        let mut adl = compile_adl(&authored, &source);
        reconcile_adl_with_dependency_census(&mut adl, &closure);
        assert_eq!(adl.constraint_results.len(), before);
        assert!(
            adl.deltas
                .iter()
                .all(|d| !d.code.starts_with("DECLARED_DEPENDENCY"))
        );
    }
}
