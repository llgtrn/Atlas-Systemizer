//! The Rust path-call resolution engine (G75): the second CALL engine.
//!
//! `adapter::resolve_path_calls` (rust-analyzer #4's `hir-def` name resolution, absorbed natively)
//! resolves every path call of every workspace crate target; this module lays out those targets
//! from the Cargo manifests in the inventory, runs the resolver, and turns each resolution into an
//! observation of the SAME CALL claim the syntactic extractor made at that anchor -- same
//! `record_id`, `dispatch: STATIC_RESOLVED`, `callees: [the callee's FunctionIdentity record]` --
//! under its own extractor identity, so the two engines stay separately attributable
//! (`.atlas/contracts/SEMANTIC-EXTRACTION.md#multi-engine-extraction`). The callee identity is
//! the syntactic extractor's own FunctionIdentity record for the definition the resolver found,
//! never a re-derived one.
//!
//! The engine evaluates TYPE (G83: a spelling whose every occurrence in an artifact resolves to
//! one canonical type is claimed as denoting it), CALL for path calls, (G79) `self.m()` and
//! (G139) typed-local `x.m()` method calls ((G140) dynamically, through a trait's declaration, when
//! the local is known only by trait bounds), and (G77) EFFECT for path calls it resolves to a
//! standard-library path the declared std-path effect table (`atlas_core::std_path_effects`)
//! names -- an effect site of the calling function, anchored at the call -- and (G117)
//! CONCURRENCY for path calls resolved to a std path the declared std-path concurrency table
//! (`atlas_core::std_path_concurrency`) names, and (G125) PERSISTENCE for path calls resolved to a
//! std path the declared std-path persistence table (`atlas_core::std_path_persistence`) names.
//! Every obligation is
//! UNKNOWN (method calls, `async` blocks, macro arguments and every other effect source are
//! outside it), and a resolution that cannot be attached -- no syntactic claim at the anchor, or
//! no FunctionIdentity for the definition -- is a diagnosed disagreement, never a fabricated
//! record.

use adapter::join_path as join;
use adapter::{
    CrateInput, DiagnosticCode, ExtractionBatch, ExtractionDiagnostic, ObligationResult,
    PathCallOutcome,
};
use atlas_core::{
    ArtifactDisposition, CallDispatchKind, EpistemicStatus, Evidence, EvidenceId,
    ExtractorIdentity, InventoryReport, Provenance, SemanticDimension, SemanticObservation,
    SemanticRecordHeader, SemanticRecordId, stable_id,
};
use std::collections::{BTreeMap, BTreeSet};
use std::{fs, path::Path};

pub const RUST_PATH_RESOLUTION_ID: &str = "atlas.resolution.rust-paths";
pub const RUST_PATH_RESOLUTION_VERSION: &str = "1";

/// The dimensions the resolution engine is asked to evaluate (accounting closure is checked
/// against these, not against every dimension).
pub const RUST_PATH_RESOLUTION_DIMENSIONS: [SemanticDimension; 6] = [
    SemanticDimension::Call,
    SemanticDimension::Concurrency,
    SemanticDimension::Effect,
    SemanticDimension::Persistence,
    SemanticDimension::Resource,
    SemanticDimension::Type,
];

/// What the engine produced for one artifact.
#[derive(Default)]
struct ArtifactWork {
    calls: Vec<SemanticObservation>,
    call_evidence: Vec<Evidence>,
    effects: Vec<SemanticObservation>,
    effect_evidence: Vec<Evidence>,
    concurrency: Vec<SemanticObservation>,
    concurrency_evidence: Vec<Evidence>,
    persistence: Vec<SemanticObservation>,
    persistence_evidence: Vec<Evidence>,
    resources: Vec<SemanticObservation>,
    resource_evidence: Vec<Evidence>,
    types: Vec<SemanticObservation>,
    type_evidence: Vec<Evidence>,
    unattached: usize,
}

fn identity() -> ExtractorIdentity {
    ExtractorIdentity {
        id: RUST_PATH_RESOLUTION_ID.into(),
        version: RUST_PATH_RESOLUTION_VERSION.into(),
    }
}

/// A manifest target path (`[lib] path`, `[[bin]] path`, `build`) resolved against the manifest's
/// directory, `.` and `..` segments collapsed, as an inventory path (G164, replay R8: crubit keeps
/// its manifests under `cargo/` and points every target at `../../../<source>.rs`). `None` when
/// the path climbs above the repository root: such a target is never a workspace source.
fn target_path(dir: &str, relative: &str) -> Option<String> {
    let joined = join(dir, relative);
    let mut parts: Vec<&str> = Vec::new();
    for part in joined.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                parts.pop()?;
            }
            other => parts.push(other),
        }
    }
    Some(parts.join("/"))
}

/// Every workspace crate target (library, binaries, build script) with the extern-prelude names
/// of the workspace libraries it may use, from the package manifests in `sources`' inventory.
pub fn crate_targets(
    manifests: &BTreeMap<String, String>,
    sources: &BTreeMap<String, String>,
) -> Vec<CrateInput> {
    struct Package {
        dir: String,
        targets: adapter::ManifestTargets,
    }
    let packages: Vec<Package> = manifests
        .iter()
        .filter_map(|(path, text)| {
            let dir = path
                .strip_suffix("Cargo.toml")?
                .trim_end_matches('/')
                .to_owned();
            let targets = adapter::manifest_targets(text, |rel| {
                target_path(&dir, rel).is_some_and(|path| sources.contains_key(&path))
            })?;
            Some(Package { dir, targets })
        })
        .collect();

    let mut crates: Vec<CrateInput> = Vec::new();
    let mut libs: BTreeMap<String, usize> = BTreeMap::new();
    let mut kinds: Vec<(usize, bool)> = Vec::new(); // (package index, is build script)
    for (index, package) in packages.iter().enumerate() {
        if let Some(root) =
            (package.targets.lib.as_deref()).and_then(|l| target_path(&package.dir, l))
        {
            libs.insert(package.targets.package.clone(), crates.len());
            crates.push(CrateInput {
                root,
                externs: BTreeMap::new(),
            });
            kinds.push((index, false));
        }
    }
    for (index, package) in packages.iter().enumerate() {
        for root in (package.targets.bins.iter()).filter_map(|b| target_path(&package.dir, b)) {
            crates.push(CrateInput {
                root,
                externs: BTreeMap::new(),
            });
            kinds.push((index, false));
        }
        if let Some(root) =
            (package.targets.build.as_deref()).and_then(|b| target_path(&package.dir, b))
        {
            crates.push(CrateInput {
                root,
                externs: BTreeMap::new(),
            });
            kinds.push((index, true));
        }
    }
    for (krate, (package_index, is_build)) in kinds.into_iter().enumerate() {
        let package = &packages[package_index].targets;
        let mut externs = BTreeMap::new();
        for (key, crate_name, role) in &package.dependencies {
            let wanted = if is_build {
                *role == atlas_core::DependencyRole::Build
            } else {
                *role != atlas_core::DependencyRole::Build
            };
            if let (true, Some(&lib)) = (wanted, libs.get(crate_name)) {
                externs.insert(key.replace('-', "_"), lib);
            }
        }
        // A binary (never the library itself or its build script) sees its own package's library.
        if !is_build
            && let Some(&lib) = libs.get(&package.package)
            && lib != krate
        {
            externs.insert(package.package.replace('-', "_"), lib);
        }
        crates[krate].externs = externs;
    }
    crates
}

/// The resolution engine's batches: one per Rust artifact (a file no crate root reaches says it
/// was not evaluated), each observing the CALL claims it resolved.
pub fn resolve_rust_path_calls(
    inventory: &InventoryReport,
    batches: &[ExtractionBatch],
) -> Vec<ExtractionBatch> {
    let root = Path::new(&inventory.root);
    let mut sources = BTreeMap::new();
    let mut manifests = BTreeMap::new();
    let mut artifacts = BTreeMap::new();
    for artifact in &inventory.artifacts {
        if artifact.disposition != ArtifactDisposition::Parsed {
            continue;
        }
        let is_manifest = artifact.path == "Cargo.toml" || artifact.path.ends_with("/Cargo.toml");
        let is_rust = artifact.language.as_deref() == Some("rust");
        if !is_manifest && !is_rust {
            continue;
        }
        let Ok(text) = fs::read_to_string(root.join(&artifact.path)) else {
            continue;
        };
        if is_manifest {
            manifests.insert(artifact.path.clone(), text);
        } else {
            artifacts.insert(artifact.path.clone(), artifact.id.clone());
            sources.insert(artifact.path.clone(), text);
        }
    }
    let crates = crate_targets(&manifests, &sources);
    let workspace = adapter::resolve_workspace(&crates, &sources);
    let resolutions = &workspace.calls;

    // The syntactic extractor's claims: CALL sites by anchor, FunctionIdentity by item start.
    let mut claims = BTreeMap::new();
    let mut functions = BTreeMap::new();
    let mut spellings: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let (mut repository, mut revision) = (None, None);
    for batch in batches {
        if batch.extractor.id != adapter::RUST_SEMANTIC_EXTRACTOR_ID {
            continue;
        }
        repository.get_or_insert_with(|| batch.repository.clone());
        revision.get_or_insert_with(|| batch.revision.clone());
        for observation in &batch.observations {
            match observation {
                SemanticObservation::Call(header) => {
                    let span = &header.subject.span;
                    claims.insert((span.path.clone(), span.line, span.column), header);
                }
                SemanticObservation::Type(header) => {
                    spellings
                        .entry(header.subject.path.clone())
                        .or_default()
                        .insert(header.subject.name.clone());
                }
                SemanticObservation::FunctionIdentity(header) => {
                    let span = &header.subject.span;
                    functions.insert(
                        (
                            span.path.clone(),
                            span.line,
                            span.column,
                            header.subject.symbol.name.clone(),
                        ),
                        header.record_id.clone(),
                    );
                }
                _ => {}
            }
        }
    }
    let (Some(repository), Some(revision)) = (repository, revision) else {
        return Vec::new();
    };

    let extractor = identity();
    let mut per_artifact: BTreeMap<String, ArtifactWork> = artifacts
        .keys()
        .map(|path| (path.clone(), ArtifactWork::default()))
        .collect();
    let provenance = |resolution: &adapter::PathCallResolution| Provenance {
        source_path: resolution.path.clone(),
        source_revision: Some(revision.clone()),
        extractor: RUST_PATH_RESOLUTION_ID.into(),
        content_hash: None,
        span: Some(format!("{}:{}", resolution.line, resolution.column)),
    };
    for resolution in resolutions {
        let entry = per_artifact.entry(resolution.path.clone()).or_default();
        let claim = claims.get(&(resolution.path.clone(), resolution.line, resolution.column));
        match &resolution.outcome {
            PathCallOutcome::Resolved(target) | PathCallOutcome::Dynamic(target) => {
                // G140: a call through a trait bound names the trait's declaration; which
                // implementation runs is decided at run time or instantiation (DYNAMIC_PARTIAL).
                let dynamic = resolution.outcome.is_dynamic();
                let callee = functions.get(&(
                    target.path.clone(),
                    target.line,
                    target.column,
                    target.name.clone(),
                ));
                let (Some(claim), Some(callee)) = (claim, callee) else {
                    entry.unattached += 1;
                    continue;
                };
                let evidence_id = EvidenceId::new(stable_id(
                    "evidence",
                    &format!("{RUST_PATH_RESOLUTION_ID}:{}", claim.record_id.as_str()),
                ));
                entry.call_evidence.push(Evidence {
                    id: evidence_id.as_str().to_owned(),
                    kind: "NAME_RESOLUTION".into(),
                    path: resolution.path.clone(),
                    summary: format!(
                        "{} `{}` at {}:{}:{} to `{}` at {}:{}:{}",
                        if dynamic {
                            "dispatched through the trait method declaration"
                        } else {
                            "resolved"
                        },
                        resolution.callee,
                        resolution.path,
                        resolution.line,
                        resolution.column,
                        target.name,
                        target.path,
                        target.line,
                        target.column
                    ),
                    revision: Some(revision.clone()),
                });
                let mut subject = claim.subject.clone();
                subject.dispatch = if dynamic {
                    CallDispatchKind::DynamicPartial
                } else {
                    CallDispatchKind::StaticResolved
                };
                subject.callees = vec![callee.clone()];
                let observation = SemanticObservation::Call(SemanticRecordHeader {
                    record_id: claim.record_id.clone(),
                    dimension: SemanticDimension::Call,
                    status: EpistemicStatus::Derived,
                    scope: claim.scope.clone(),
                    repository: repository.clone(),
                    revision: revision.clone(),
                    extractor: extractor.clone(),
                    evidence_refs: vec![evidence_id],
                    provenance: provenance(resolution),
                    subject,
                });
                assert!(observation.is_dimension_consistent());
                entry.calls.push(observation);
            }
            // G77: a call resolved to a standard-library path whose effects the declared table
            // names is an effect site of the calling function, anchored at the call.
            PathCallOutcome::External(path) => {
                let categories = atlas_core::std_path_effects(path);
                let concurrency = atlas_core::std_path_concurrency(path);
                let persistence = atlas_core::std_path_persistence(path);
                let resource = atlas_core::std_path_resource(path);
                if categories.is_empty()
                    && concurrency.is_none()
                    && persistence.is_none()
                    && resource.is_none()
                {
                    continue;
                }
                let Some(claim) = claim else {
                    entry.unattached += 1;
                    continue;
                };
                // G117: a call resolved to a std path the declared concurrency table names is a
                // concurrency site of the calling function, anchored at the call.
                if let Some(kind) = concurrency {
                    let subject = atlas_core::ConcurrencyIdentity {
                        repository: repository.clone(),
                        revision: revision.clone(),
                        function: claim.subject.function.clone(),
                        kind,
                        span: claim.subject.span.clone(),
                    };
                    let record_id = SemanticRecordId::new(
                        SemanticDimension::Concurrency,
                        &subject.identity_key(),
                    );
                    let evidence_id = EvidenceId::new(stable_id(
                        "evidence",
                        &format!("{RUST_PATH_RESOLUTION_ID}:{}", record_id.as_str()),
                    ));
                    entry.concurrency_evidence.push(Evidence {
                        id: evidence_id.as_str().to_owned(),
                        kind: "NAME_RESOLUTION".into(),
                        path: resolution.path.clone(),
                        summary: format!(
                            "`{}` at {}:{}:{} resolves to `{path}`: {} (declared std-path concurrency table)",
                            resolution.callee,
                            resolution.path,
                            resolution.line,
                            resolution.column,
                            kind.as_str()
                        ),
                        revision: Some(revision.clone()),
                    });
                    let observation = SemanticObservation::Concurrency(SemanticRecordHeader {
                        record_id,
                        dimension: SemanticDimension::Concurrency,
                        status: EpistemicStatus::Derived,
                        scope: claim.scope.clone(),
                        repository: repository.clone(),
                        revision: revision.clone(),
                        extractor: extractor.clone(),
                        evidence_refs: vec![evidence_id],
                        provenance: provenance(resolution),
                        subject,
                    });
                    assert!(observation.is_dimension_consistent());
                    entry.concurrency.push(observation);
                }
                // G125: a call resolved to a std path the declared persistence table names is a
                // persistence site of the calling function, anchored at the call; the resolved API
                // is the evidence (`Resolved`), the place it touches is not claimed.
                if let Some(kind) = persistence {
                    let subject = atlas_core::PersistenceIdentity {
                        repository: repository.clone(),
                        revision: revision.clone(),
                        function: claim.subject.function.clone(),
                        kind,
                        span: claim.subject.span.clone(),
                        place: atlas_core::PlaceRef::Unresolved,
                        resolution: atlas_core::PersistenceResolution::Resolved,
                    };
                    let record_id = SemanticRecordId::new(
                        SemanticDimension::Persistence,
                        &subject.identity_key(),
                    );
                    let evidence_id = EvidenceId::new(stable_id(
                        "evidence",
                        &format!("{RUST_PATH_RESOLUTION_ID}:{}", record_id.as_str()),
                    ));
                    entry.persistence_evidence.push(Evidence {
                        id: evidence_id.as_str().to_owned(),
                        kind: "NAME_RESOLUTION".into(),
                        path: resolution.path.clone(),
                        summary: format!(
                            "`{}` at {}:{}:{} resolves to `{path}`: {} (declared std-path persistence table)",
                            resolution.callee,
                            resolution.path,
                            resolution.line,
                            resolution.column,
                            kind.as_str()
                        ),
                        revision: Some(revision.clone()),
                    });
                    let observation = SemanticObservation::Persistence(SemanticRecordHeader {
                        record_id,
                        dimension: SemanticDimension::Persistence,
                        status: EpistemicStatus::Derived,
                        scope: claim.scope.clone(),
                        repository: repository.clone(),
                        revision: revision.clone(),
                        extractor: extractor.clone(),
                        evidence_refs: vec![evidence_id],
                        provenance: provenance(resolution),
                        subject,
                    });
                    assert!(observation.is_dimension_consistent());
                    entry.persistence.push(observation);
                }
                // G157: a call resolved to a std path the declared resource table names acquires
                // a resource in the calling function, anchored at the call.
                if let Some(kind) = resource {
                    let subject = atlas_core::ResourceIdentity {
                        repository: repository.clone(),
                        revision: revision.clone(),
                        function: claim.subject.function.clone(),
                        operation: atlas_core::ResourceOperation::Acquire,
                        kind,
                        span: claim.subject.span.clone(),
                        acquired_at: None,
                        release: None,
                        holder: String::new(),
                    };
                    let record_id =
                        SemanticRecordId::new(SemanticDimension::Resource, &subject.identity_key());
                    let evidence_id = EvidenceId::new(stable_id(
                        "evidence",
                        &format!("{RUST_PATH_RESOLUTION_ID}:{}", record_id.as_str()),
                    ));
                    entry.resource_evidence.push(Evidence {
                        id: evidence_id.as_str().to_owned(),
                        kind: "NAME_RESOLUTION".into(),
                        path: resolution.path.clone(),
                        summary: format!(
                            "`{}` at {}:{}:{} resolves to `{path}`: ACQUIRE {} (declared std-path resource table)",
                            resolution.callee,
                            resolution.path,
                            resolution.line,
                            resolution.column,
                            kind.as_str()
                        ),
                        revision: Some(revision.clone()),
                    });
                    let observation = SemanticObservation::Resource(SemanticRecordHeader {
                        record_id,
                        dimension: SemanticDimension::Resource,
                        status: EpistemicStatus::Derived,
                        scope: claim.scope.clone(),
                        repository: repository.clone(),
                        revision: revision.clone(),
                        extractor: extractor.clone(),
                        evidence_refs: vec![evidence_id],
                        provenance: provenance(resolution),
                        subject,
                    });
                    assert!(observation.is_dimension_consistent());
                    entry.resources.push(observation);
                }
                for &category in categories {
                    let subject = atlas_core::EffectIdentity {
                        repository: repository.clone(),
                        revision: revision.clone(),
                        function: claim.subject.function.clone(),
                        category,
                        span: claim.subject.span.clone(),
                    };
                    let record_id =
                        SemanticRecordId::new(SemanticDimension::Effect, &subject.identity_key());
                    let evidence_id = EvidenceId::new(stable_id(
                        "evidence",
                        &format!("{RUST_PATH_RESOLUTION_ID}:{}", record_id.as_str()),
                    ));
                    entry.effect_evidence.push(Evidence {
                        id: evidence_id.as_str().to_owned(),
                        kind: "NAME_RESOLUTION".into(),
                        path: resolution.path.clone(),
                        summary: format!(
                            "`{}` at {}:{}:{} resolves to `{path}`: {} (declared std-path effect table)",
                            resolution.callee,
                            resolution.path,
                            resolution.line,
                            resolution.column,
                            category.as_str()
                        ),
                        revision: Some(revision.clone()),
                    });
                    let observation = SemanticObservation::Effect(SemanticRecordHeader {
                        record_id,
                        dimension: SemanticDimension::Effect,
                        status: EpistemicStatus::Derived,
                        scope: claim.scope.clone(),
                        repository: repository.clone(),
                        revision: revision.clone(),
                        extractor: extractor.clone(),
                        evidence_refs: vec![evidence_id],
                        provenance: provenance(resolution),
                        subject,
                    });
                    assert!(observation.is_dimension_consistent());
                    entry.effects.push(observation);
                }
            }
            PathCallOutcome::Unresolved(_) => {}
        }
    }

    // G83: a spelling the syntactic extractor recorded in an artifact denotes one canonical type
    // when every occurrence of it there resolves to that type.
    // G157: where a let-bound resource is given back. A release is attached to the syntactic
    // CALL claim of the acquiring call (its function and scope); a scope-end release rests on a
    // syntactic move check (INFERRED), a resolved `drop` or `join` on name resolution (DERIVED).
    for release in &workspace.releases {
        let entry = per_artifact.entry(release.path.clone()).or_default();
        let Some(claim) =
            claims.get(&(release.path.clone(), release.acquired.0, release.acquired.1))
        else {
            entry.unattached += 1;
            continue;
        };
        let acquired_at = claim.subject.span.clone();
        let subject = atlas_core::ResourceIdentity {
            repository: repository.clone(),
            revision: revision.clone(),
            function: claim.subject.function.clone(),
            operation: atlas_core::ResourceOperation::Release,
            kind: release.kind,
            span: atlas_core::SourceSpan {
                path: release.path.clone(),
                line: release.line,
                column: release.column,
            },
            acquired_at: Some(acquired_at.clone()),
            release: Some(release.release),
            holder: release.holder.clone(),
        };
        debug_assert!(subject.is_well_formed());
        let status = match release.release {
            atlas_core::ResourceRelease::ScopeEnd => EpistemicStatus::Inferred,
            atlas_core::ResourceRelease::ExplicitDrop | atlas_core::ResourceRelease::Join => {
                EpistemicStatus::Derived
            }
        };
        let record_id = SemanticRecordId::new(SemanticDimension::Resource, &subject.identity_key());
        let evidence_id = EvidenceId::new(stable_id(
            "evidence",
            &format!("{RUST_PATH_RESOLUTION_ID}:{}", record_id.as_str()),
        ));
        entry.resource_evidence.push(Evidence {
            id: evidence_id.as_str().to_owned(),
            kind: "NAME_RESOLUTION".into(),
            path: release.path.clone(),
            summary: format!(
                "`{}` holds the {} acquired at {}:{}:{}; released at {}:{} by {}{}",
                release.holder,
                release.kind.as_str(),
                acquired_at.path,
                acquired_at.line,
                acquired_at.column,
                release.line,
                release.column,
                release.release.as_str(),
                if release.release == atlas_core::ResourceRelease::ScopeEnd {
                    " (the holder is never moved: syntactic move check)"
                } else {
                    ""
                }
            ),
            revision: Some(revision.clone()),
        });
        let observation = SemanticObservation::Resource(SemanticRecordHeader {
            record_id,
            dimension: SemanticDimension::Resource,
            status,
            scope: claim.scope.clone(),
            repository: repository.clone(),
            revision: revision.clone(),
            extractor: extractor.clone(),
            evidence_refs: vec![evidence_id],
            provenance: Provenance {
                source_path: release.path.clone(),
                source_revision: Some(revision.clone()),
                extractor: RUST_PATH_RESOLUTION_ID.into(),
                content_hash: None,
                span: Some(format!("{}:{}", release.line, release.column)),
            },
            subject,
        });
        assert!(observation.is_dimension_consistent());
        entry.resources.push(observation);
    }

    let mut meanings: BTreeMap<(&str, &str), BTreeSet<Option<&str>>> = BTreeMap::new();
    for occurrence in &workspace.types {
        meanings
            .entry((occurrence.path.as_str(), occurrence.spelling.as_str()))
            .or_default()
            .insert(occurrence.canonical.as_deref());
    }
    for ((path, spelling), canonicals) in meanings {
        let canonicals: Vec<Option<&str>> = canonicals.into_iter().collect();
        let ([Some(canonical)], Some(entry)) = (canonicals.as_slice(), per_artifact.get_mut(path))
        else {
            continue;
        };
        if !spellings.get(path).is_some_and(|s| s.contains(spelling)) {
            continue;
        }
        let subject = atlas_core::TypeIdentity {
            repository: repository.clone(),
            revision: revision.clone(),
            scope: atlas_core::SemanticScope::new(Vec::<String>::new()),
            name: spelling.to_owned(),
            canonical: Some((*canonical).to_owned()),
            path: String::new(),
        };
        let record_id = SemanticRecordId::new(SemanticDimension::Type, &subject.identity_key());
        let evidence_id = EvidenceId::new(stable_id(
            "evidence",
            &format!("{RUST_PATH_RESOLUTION_ID}:{path}:{}", record_id.as_str()),
        ));
        entry.type_evidence.push(Evidence {
            id: evidence_id.as_str().to_owned(),
            kind: "NAME_RESOLUTION".into(),
            path: path.to_owned(),
            summary: format!("type `{spelling}` in {path} denotes `{canonical}`"),
            revision: Some(revision.clone()),
        });
        let observation = SemanticObservation::Type(SemanticRecordHeader {
            record_id,
            dimension: SemanticDimension::Type,
            status: EpistemicStatus::Derived,
            scope: atlas_core::SemanticScope::new(Vec::<String>::new()),
            repository: repository.clone(),
            revision: revision.clone(),
            extractor: extractor.clone(),
            evidence_refs: vec![evidence_id],
            provenance: Provenance {
                source_path: path.to_owned(),
                source_revision: Some(revision.clone()),
                extractor: RUST_PATH_RESOLUTION_ID.into(),
                content_hash: None,
                span: None,
            },
            subject,
        });
        assert!(observation.is_dimension_consistent());
        entry.types.push(observation);
    }

    // G162: the path calls withheld because a scope is open, by artifact.
    let mut withheld: BTreeMap<&str, Vec<&adapter::WithheldPath>> = BTreeMap::new();
    for w in &workspace.withheld {
        withheld.entry(w.path.as_str()).or_default().push(w);
    }
    let mut out = Vec::new();
    for (path, work) in per_artifact {
        let Some(artifact) = artifacts.get(&path) else {
            continue;
        };
        let reached = workspace.reached.contains(&path);
        let concurrency_scope = if reached {
            format!(
                "{RUST_PATH_RESOLUTION_ID} derives concurrency only for path calls resolved to a standard-library path the declared std-path concurrency table names ({path}); method calls (spawn_scoped, lock, send, recv, atomics), macro arguments and paths withheld in open scopes are outside it"
            )
        } else {
            format!(
                "{RUST_PATH_RESOLUTION_ID} did not evaluate {path}: no Cargo target's module tree reaches it"
            )
        };
        let persistence_scope = if reached {
            format!(
                "{RUST_PATH_RESOLUTION_ID} derives persistence for path calls resolved to a standard-library path the declared std-path persistence table names, and (G144) for declared inherent std methods on receivers whose std type is known ({path}); trait methods (flush), non-std storage, untyped receivers and macro arguments are outside it"
            )
        } else {
            format!(
                "{RUST_PATH_RESOLUTION_ID} did not evaluate {path}: no Cargo target's module tree reaches it"
            )
        };
        let resource_scope = if reached {
            format!(
                "{RUST_PATH_RESOLUTION_ID} derives resource acquisitions for calls resolved to a standard-library path the declared std-path resource table names (files, sockets, std lock guards on receivers whose std type is known, threads), and releases for a holder bound once by a `let` and never moved: at its block's end (INFERRED), at a resolved `drop` or `join` statement (DERIVED) ({path}); temporaries, moved holders, fields and statics, non-std resources, FFI acquire/release pairs and macro arguments are outside it"
            )
        } else {
            format!(
                "{RUST_PATH_RESOLUTION_ID} did not evaluate {path}: no Cargo target's module tree reaches it"
            )
        };
        let (call_scope, effect_scope, type_scope) = if reached {
            (
                format!(
                    "{RUST_PATH_RESOLUTION_ID} resolves path calls, and `self.m()` and `x.m()` calls on a local whose declared type is a plain workspace type (G139) or known only by workspace-trait bounds (G140, DYNAMIC_PARTIAL to the trait's declaration), or bound once by a `let` to a call or literal whose callee declares a plain workspace type (G142), or a field or call result such types declare (G143), or a std receiver calling a declared inherent std method (G144, the std path the effect, persistence and concurrency tables read), decided by the method probe's first step or, where no by-value method can come first, its autoref step (G142) ({path}), in closure and `async` block bodies too (G133, G159); other method calls, macro arguments and paths withheld in open scopes (G162) are outside it"
                ),
                format!(
                    "{RUST_PATH_RESOLUTION_ID} derives effects only for path calls resolved to a standard-library path the declared std-path effect table names ({path}); method calls and every other effect source are outside it"
                ),
                format!(
                    "{RUST_PATH_RESOLUTION_ID} canonicalizes only type spellings every occurrence of which in {path} resolves to one type; generic, opaque and unresolvable spellings are outside it"
                ),
            )
        } else {
            let unreached = format!(
                "{RUST_PATH_RESOLUTION_ID} did not evaluate {path}: no Cargo target's module tree reaches it"
            );
            (unreached.clone(), unreached.clone(), unreached)
        };
        let call_diagnostic = ExtractionDiagnostic::new(
            DiagnosticCode::IncompleteAnalysis,
            Some(SemanticDimension::Call),
            call_scope,
        );
        let effect_diagnostic = ExtractionDiagnostic::new(
            DiagnosticCode::IncompleteAnalysis,
            Some(SemanticDimension::Effect),
            effect_scope,
        );
        let mut call_obligation = ObligationResult::unknown_with_observations(
            SemanticDimension::Call,
            work.calls.iter().map(|o| o.record_id().clone()).collect(),
            ids(&work.call_evidence),
            call_diagnostic.id.clone(),
        );
        let effect_obligation = ObligationResult::unknown_with_observations(
            SemanticDimension::Effect,
            work.effects.iter().map(|o| o.record_id().clone()).collect(),
            ids(&work.effect_evidence),
            effect_diagnostic.id.clone(),
        );
        let concurrency_diagnostic = ExtractionDiagnostic::new(
            DiagnosticCode::IncompleteAnalysis,
            Some(SemanticDimension::Concurrency),
            concurrency_scope,
        );
        let concurrency_obligation = ObligationResult::unknown_with_observations(
            SemanticDimension::Concurrency,
            work.concurrency
                .iter()
                .map(|o| o.record_id().clone())
                .collect(),
            ids(&work.concurrency_evidence),
            concurrency_diagnostic.id.clone(),
        );
        let persistence_diagnostic = ExtractionDiagnostic::new(
            DiagnosticCode::IncompleteAnalysis,
            Some(SemanticDimension::Persistence),
            persistence_scope,
        );
        let persistence_obligation = ObligationResult::unknown_with_observations(
            SemanticDimension::Persistence,
            work.persistence
                .iter()
                .map(|o| o.record_id().clone())
                .collect(),
            ids(&work.persistence_evidence),
            persistence_diagnostic.id.clone(),
        );
        let resource_diagnostic = ExtractionDiagnostic::new(
            DiagnosticCode::IncompleteAnalysis,
            Some(SemanticDimension::Resource),
            resource_scope,
        );
        let resource_obligation = ObligationResult::unknown_with_observations(
            SemanticDimension::Resource,
            work.resources
                .iter()
                .map(|o| o.record_id().clone())
                .collect(),
            ids(&work.resource_evidence),
            resource_diagnostic.id.clone(),
        );
        let type_diagnostic = ExtractionDiagnostic::new(
            DiagnosticCode::IncompleteAnalysis,
            Some(SemanticDimension::Type),
            type_scope,
        );
        let type_obligation = ObligationResult::unknown_with_observations(
            SemanticDimension::Type,
            work.types.iter().map(|o| o.record_id().clone()).collect(),
            ids(&work.type_evidence),
            type_diagnostic.id.clone(),
        );
        let mut diagnostics = vec![
            call_diagnostic,
            concurrency_diagnostic,
            effect_diagnostic,
            persistence_diagnostic,
            resource_diagnostic,
            type_diagnostic,
        ];
        if let Some(calls) = withheld.get(path.as_str()) {
            let open = ExtractionDiagnostic::new(
                DiagnosticCode::IncompleteAnalysis,
                Some(SemanticDimension::Call),
                open_scope_message(&path, calls),
            );
            call_obligation.diagnostics.push(open.id.clone());
            diagnostics.push(open);
        }
        if work.unattached > 0 {
            let disagreement = ExtractionDiagnostic::new(
                DiagnosticCode::IncompleteAnalysis,
                Some(SemanticDimension::Call),
                format!(
                    "{} resolved path call(s) in {path} match no syntactic CALL claim or no FunctionIdentity (engine disagreement)",
                    work.unattached
                ),
            );
            call_obligation.diagnostics.push(disagreement.id.clone());
            diagnostics.push(disagreement);
        }
        let mut observations = work.calls;
        observations.extend(work.concurrency);
        observations.extend(work.effects);
        observations.extend(work.persistence);
        observations.extend(work.resources);
        observations.extend(work.types);
        let mut evidence = work.call_evidence;
        evidence.extend(work.concurrency_evidence);
        evidence.extend(work.effect_evidence);
        evidence.extend(work.persistence_evidence);
        evidence.extend(work.resource_evidence);
        evidence.extend(work.type_evidence);
        out.push(ExtractionBatch {
            extractor: extractor.clone(),
            repository: repository.clone(),
            revision: revision.clone(),
            artifact: artifact.clone(),
            input_fingerprint: stable_id(
                "resolution-input",
                &format!("{RUST_PATH_RESOLUTION_ID}:{}:{path}", revision.value),
            ),
            observations,
            evidence,
            obligations: vec![
                call_obligation,
                concurrency_obligation,
                effect_obligation,
                persistence_obligation,
                resource_obligation,
                type_obligation,
            ],
            diagnostics,
        });
    }
    out
}

fn ids(evidence: &[Evidence]) -> Vec<EvidenceId> {
    evidence
        .iter()
        .map(|e| EvidenceId::new(e.id.clone()))
        .collect()
}

/// G162: the open-scope diagnostic of one artifact -- how many path calls are withheld, and for
/// each cause how many and the first of them.
fn open_scope_message(path: &str, calls: &[&adapter::WithheldPath]) -> String {
    let mut by_cause: BTreeMap<&str, Vec<&adapter::WithheldPath>> = BTreeMap::new();
    for call in calls {
        by_cause.entry(call.cause.as_str()).or_default().push(call);
    }
    let causes: Vec<String> = by_cause
        .into_iter()
        .map(|(cause, calls)| {
            let first = calls[0];
            format!(
                "{cause} ({} call(s), first `{}` at line {})",
                calls.len(),
                first.callee,
                first.line
            )
        })
        .collect();
    format!(
        "{}{} path call(s) in {path} withheld: a name on their path is looked up in an open scope, which a macro-expanded item may extend (Rust lets one shadow a glob import or the extern prelude, `std` included); {}",
        atlas_core::OPEN_SCOPE_DIAGNOSTIC,
        calls.len(),
        causes.join("; ")
    )
}

#[cfg(test)]
mod tests;
