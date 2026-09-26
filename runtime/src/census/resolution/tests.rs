use super::*;
use crate::census::extraction::{
    CensusExtractionAccounting, extract_semantics, requested_dimensions,
};
use atlas_core::{ArtifactId, ArtifactKind, ArtifactRecord, RepositoryId, RevisionRef};
use std::time::{SystemTime, UNIX_EPOCH};

fn map(entries: &[(&str, &str)]) -> BTreeMap<String, String> {
    entries
        .iter()
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

#[test]
fn crate_targets_follow_manifests_renames_roles_and_own_library() {
    let manifests = map(&[
        ("Cargo.toml", "[workspace]\nmembers = [\"core\", \"app\"]\n"),
        ("core/Cargo.toml", "[package]\nname = \"core\"\n"),
        (
            "app/Cargo.toml",
            "[package]\nname = \"atlas-app\"\n\n[dependencies]\natlas_core = { package = \"core\", path = \"../core\" }\nserde = \"1\"\n\n[build-dependencies]\nbuild_core = { package = \"core\", path = \"../core\" }\n",
        ),
    ]);
    let sources = map(&[
        ("core/src/lib.rs", ""),
        ("app/src/lib.rs", ""),
        ("app/src/main.rs", ""),
        ("app/build.rs", ""),
    ]);
    let crates = crate_targets(&manifests, &sources);
    let described: Vec<(String, Vec<(String, String)>)> = crates
        .iter()
        .map(|c| {
            (
                c.root.clone(),
                c.externs
                    .iter()
                    .map(|(name, index)| (name.clone(), crates[*index].root.clone()))
                    .collect(),
            )
        })
        .collect();
    let s = |v: &str| v.to_owned();
    assert_eq!(
        described,
        [
            (
                s("app/src/lib.rs"),
                vec![(s("atlas_core"), s("core/src/lib.rs"))]
            ),
            (s("core/src/lib.rs"), vec![]),
            (
                s("app/src/main.rs"),
                vec![
                    (s("atlas_app"), s("app/src/lib.rs")),
                    (s("atlas_core"), s("core/src/lib.rs")),
                ]
            ),
            (
                s("app/build.rs"),
                vec![(s("build_core"), s("core/src/lib.rs"))]
            ),
        ]
    );
}

/// G164 (replay R8, crubit): a manifest may keep its targets outside its own directory
/// (`cargo/x/Cargo.toml` with `[lib] path = "../../x.rs"`); the crate root is the normalized
/// inventory path, its dependencies bind through it, and a target climbing above the repository
/// root is no crate at all.
#[test]
fn crate_targets_normalize_climbing_target_paths_and_refuse_escapes() {
    let manifests = map(&[
        (
            "cargo/tool/Cargo.toml",
            "[package]\nname = \"tool\"\n\n[[bin]]\nname = \"tool\"\npath = \"../../tool/./main.rs\"\n\n[dependencies]\ncmdline = { path = \"../cmdline\", package = \"tool_cmdline\" }\n",
        ),
        (
            "cargo/cmdline/Cargo.toml",
            "[package]\nname = \"tool_cmdline\"\n\n[lib]\npath = \"../../tool/cmdline.rs\"\n",
        ),
        (
            "cargo/escape/Cargo.toml",
            "[package]\nname = \"escape\"\n\n[lib]\npath = \"../../../outside.rs\"\n",
        ),
    ]);
    let sources = map(&[
        ("tool/main.rs", ""),
        ("tool/cmdline.rs", ""),
        ("outside.rs", ""),
    ]);
    let crates = crate_targets(&manifests, &sources);
    let described: Vec<(String, Vec<(String, String)>)> = crates
        .iter()
        .map(|c| {
            (
                c.root.clone(),
                c.externs
                    .iter()
                    .map(|(name, index)| (name.clone(), crates[*index].root.clone()))
                    .collect(),
            )
        })
        .collect();
    let s = |v: &str| v.to_owned();
    assert_eq!(
        described,
        [
            (s("tool/cmdline.rs"), vec![]),
            (
                s("tool/main.rs"),
                vec![(s("cmdline"), s("tool/cmdline.rs"))]
            ),
        ]
    );
    assert_eq!(target_path("a/b", "../../c.rs").as_deref(), Some("c.rs"));
    assert_eq!(target_path("a", "./b/../c.rs").as_deref(), Some("a/c.rs"));
    assert_eq!(target_path("a", "../../c.rs"), None);
    assert_eq!(target_path("", "src/lib.rs").as_deref(), Some("src/lib.rs"));
}

fn artifact(path: &str, language: &str) -> ArtifactRecord {
    ArtifactRecord {
        id: ArtifactId::new(format!("artifact:{path}")),
        path: path.to_owned(),
        kind: ArtifactKind::File,
        bytes: 0,
        disposition: ArtifactDisposition::Parsed,
        language: Some(language.into()),
        reason: None,
        content_digest: None,
        content_digest_withheld: None,
    }
}

fn workspace() -> (std::path::PathBuf, InventoryReport) {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "atlas-g75-resolution-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(dir.join("core/src")).unwrap();
    fs::write(dir.join("core/Cargo.toml"), "[package]\nname = \"core\"\n").unwrap();
    fs::write(
        dir.join("core/src/lib.rs"),
        "pub mod a;\npub mod io;\npub fn f() {\n    a::g();\n    helper();\n    x.method();\n}\nfn helper() {}\n",
    )
    .unwrap();
    fs::write(
        dir.join("core/src/io.rs"),
        "use std::fs;\nuse std::fs::File;\npub fn save() {\n    fs::write(\"a\", \"b\");\n    File::open(\"a\");\n    fs::copy(\"a\", \"b\");\n    std::env::var(\"X\"); std::time::Instant::now();\n    std::mem::size_of::<u128>();\n}\npub struct Status;\npub fn typed<T>(a: Status, b: crate::io::Status, c: Vec<Status>, d: File, e: T) {}\npub struct Other;\npub fn plain(o: Other) {}\npub fn shadow<Other>(o: Other) {}\n",
    )
    .unwrap();
    fs::write(dir.join("core/src/a.rs"), "pub fn g() {}\n").unwrap();
    let inventory = InventoryReport::new(
        dir.to_string_lossy().into_owned(),
        vec![
            artifact("core/Cargo.toml", "toml"),
            artifact("core/src/lib.rs", "rust"),
            artifact("core/src/a.rs", "rust"),
            artifact("core/src/io.rs", "rust"),
        ],
    );
    (dir, inventory)
}

fn revision() -> RevisionRef {
    RevisionRef {
        kind: "git".into(),
        value: "abc123".into(),
    }
}

#[test]
fn resolutions_observe_the_syntactic_claims_and_name_their_callee_identity() {
    let (dir, inventory) = workspace();
    let batches = extract_semantics(&inventory, RepositoryId::new("atlas-studio"), revision());
    let resolution = resolve_rust_path_calls(&inventory, &batches);
    assert_eq!(resolution.len(), 3, "one batch per reached Rust artifact");

    let calls = |batch: &ExtractionBatch| -> Vec<atlas_core::SemanticRecordHeader<atlas_core::CallSiteIdentity>> {
        batch
            .observations
            .iter()
            .filter_map(|o| match o {
                SemanticObservation::Call(h) => Some(h.clone()),
                _ => None,
            })
            .collect()
    };
    let syntactic_lib = batches
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/lib.rs")
        .unwrap();
    let lib = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/lib.rs")
        .unwrap();
    let resolved = calls(lib);
    assert_eq!(
        resolved.len(),
        2,
        "a::g() and helper(); never the method call"
    );
    let functions: BTreeMap<String, SemanticRecordId> = batches
        .iter()
        .flat_map(|b| &b.observations)
        .filter_map(|o| match o {
            SemanticObservation::FunctionIdentity(h) => {
                Some((h.subject.symbol.name.clone(), h.record_id.clone()))
            }
            _ => None,
        })
        .collect();
    for call in &resolved {
        // The same claim the syntactic extractor made.
        let claim = calls(syntactic_lib)
            .into_iter()
            .find(|c| c.record_id == call.record_id)
            .expect("a resolution observes an existing CALL claim");
        assert_eq!(claim.subject.span, call.subject.span);
        assert_eq!(claim.subject.dispatch, CallDispatchKind::Unresolved);
        assert_eq!(call.subject.dispatch, CallDispatchKind::StaticResolved);
        assert_eq!(call.extractor.id, RUST_PATH_RESOLUTION_ID);
        assert_eq!(call.status, EpistemicStatus::Derived);
    }
    let callees: Vec<&SemanticRecordId> = resolved.iter().map(|c| &c.subject.callees[0]).collect();
    assert_eq!(callees, [&functions["g"], &functions["helper"]]);

    // The engine accounts for CALL and EFFECT only, and closure holds per engine.
    let dimensions: Vec<SemanticDimension> = lib.obligations.iter().map(|o| o.dimension).collect();
    assert_eq!(dimensions, RUST_PATH_RESOLUTION_DIMENSIONS);
    assert!(
        lib.obligations
            .iter()
            .all(|o| o.status == EpistemicStatus::Unknown)
    );
    let mut accounting = CensusExtractionAccounting::new();
    for batch in batches.iter().chain(&resolution) {
        accounting.record_batch(batch);
    }
    assert!(accounting.is_closed_per_extractor(requested_dimensions));
    assert!(
        !accounting.is_closed(&crate::census::extraction::ALL_SEMANTIC_DIMENSIONS),
        "the resolution engine is not asked for every dimension"
    );

    // Two engines' observations of one claim are not a normalization conflict.
    let all: Vec<ExtractionBatch> = batches.iter().chain(&resolution).cloned().collect();
    let source = adapter::source_report_from_inventory(&inventory);
    let adl = atlas_core::compile_adl(&[], &source);
    let census = crate::census::build_census(&inventory, &source, &adl, &all, &revision());
    let normalized = crate::normalize::normalize(&census);
    assert!(normalized.conflict_candidates.is_empty());
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_resolution_without_a_syntactic_claim_is_a_diagnosed_disagreement() {
    let (dir, inventory) = workspace();
    let mut batches = extract_semantics(&inventory, RepositoryId::new("atlas-studio"), revision());
    // Drop the syntactic claims for `a::g()` (lib.rs line 4) and for the effectful `fs::write`
    // (io.rs line 4), and keep the others.
    let mut dropped = None;
    for batch in &mut batches {
        batch.observations.retain(|o| match o {
            SemanticObservation::Call(h)
                if h.subject.span.path == "core/src/lib.rs" && h.subject.span.line == 4 =>
            {
                dropped = Some(h.record_id.clone());
                false
            }
            SemanticObservation::Call(h)
                if h.subject.span.path == "core/src/io.rs" && h.subject.span.line == 4 =>
            {
                false
            }
            _ => true,
        });
    }
    let dropped = dropped.expect("the a::g() claim existed");
    let resolution = resolve_rust_path_calls(&inventory, &batches);
    let lib = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/lib.rs")
        .unwrap();
    let observed: Vec<&SemanticRecordId> = lib.observations.iter().map(|o| o.record_id()).collect();
    assert_eq!(
        observed.len(),
        1,
        "only helper() still has a claim to observe"
    );
    assert!(!observed.contains(&&dropped), "never a fabricated claim");
    assert!(
        lib.diagnostics
            .iter()
            .any(|d| d.message.starts_with("1 resolved path call(s)")),
        "{:#?}",
        lib.diagnostics
    );
    assert_eq!(lib.obligations[0].diagnostics.len(), 2);
    // An effect needs the caller its claim names: none is derived for the unclaimed call.
    let io = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/io.rs")
        .unwrap();
    let effect_lines: Vec<usize> = io
        .observations
        .iter()
        .filter_map(|o| match o {
            SemanticObservation::Effect(h) => Some(h.subject.span.line),
            _ => None,
        })
        .collect();
    assert_eq!(effect_lines, [5, 6, 6, 7, 7]);
    assert!(
        io.diagnostics
            .iter()
            .any(|d| d.message.starts_with("1 resolved path call(s)"))
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn resolved_standard_library_paths_are_effect_sites_of_the_caller() {
    let (dir, inventory) = workspace();
    let batches = extract_semantics(&inventory, RepositoryId::new("atlas-studio"), revision());
    let resolution = resolve_rust_path_calls(&inventory, &batches);
    let io = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/io.rs")
        .unwrap();
    let effects: Vec<(usize, &str)> = io
        .observations
        .iter()
        .filter_map(|o| match o {
            SemanticObservation::Effect(h) => {
                Some((h.subject.span.line, h.subject.category.as_str()))
            }
            _ => None,
        })
        .collect();
    // fs::write, File::open, fs::copy (read and write), std::env::var and Instant::now (G91);
    // never std::mem::size_of (not declared).
    assert_eq!(
        effects,
        [
            (4, "FILESYSTEM_WRITE"),
            (5, "FILESYSTEM_READ"),
            (6, "FILESYSTEM_READ"),
            (6, "FILESYSTEM_WRITE"),
            (7, "ENVIRONMENT_READ"),
            (7, "CLOCK_READ"),
        ]
    );
    let save = batches
        .iter()
        .flat_map(|b| &b.observations)
        .find_map(|o| match o {
            SemanticObservation::FunctionIdentity(h) if h.subject.symbol.name == "save" => {
                Some(h.record_id.clone())
            }
            _ => None,
        })
        .unwrap();
    for observation in &io.observations {
        if let SemanticObservation::Effect(h) = observation {
            assert_eq!(h.subject.function, save, "the caller owns the effect");
            assert_eq!(h.status, EpistemicStatus::Derived);
            assert_eq!(h.extractor.id, RUST_PATH_RESOLUTION_ID);
        }
    }
    let effect = io
        .obligations
        .iter()
        .find(|o| o.dimension == SemanticDimension::Effect)
        .unwrap();
    assert_eq!(effect.observation_ids.len(), 6);
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_type_spelling_resolved_everywhere_in_its_artifact_is_a_canonical_type_claim() {
    let (dir, inventory) = workspace();
    let batches = extract_semantics(&inventory, RepositoryId::new("atlas-studio"), revision());
    let resolution = resolve_rust_path_calls(&inventory, &batches);
    let io = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/io.rs")
        .unwrap();
    let claims: BTreeMap<String, String> = io
        .observations
        .iter()
        .filter_map(|o| match o {
            SemanticObservation::Type(h) => {
                Some((h.subject.name.clone(), h.subject.canonical.clone().unwrap()))
            }
            _ => None,
        })
        .collect();
    // Two spellings of one type share its canonical identity; a generic parameter has none.
    assert_eq!(
        claims.get("Status").map(String::as_str),
        Some("core io/Status#")
    );
    assert_eq!(
        claims.get("crate::io::Status").map(String::as_str),
        Some("core io/Status#")
    );
    assert_eq!(
        claims.get("Vec<Status>").map(String::as_str),
        Some("std::vec::Vec<core io/Status#>")
    );
    assert_eq!(
        claims.get("File").map(String::as_str),
        Some("std::fs::File")
    );
    assert!(!claims.contains_key("T"));
    // `Other` means the struct in one function and a generic parameter in another: no claim.
    assert!(!claims.contains_key("Other"));
    // Every claim names a spelling the syntactic extractor recorded in this artifact.
    let recorded: std::collections::BTreeSet<String> = batches
        .iter()
        .flat_map(|b| &b.observations)
        .filter_map(|o| match o {
            SemanticObservation::Type(h) if h.subject.path == "core/src/io.rs" => {
                Some(h.subject.name.clone())
            }
            _ => None,
        })
        .collect();
    assert!(claims.keys().all(|spelling| recorded.contains(spelling)));
    for observation in &io.observations {
        if let SemanticObservation::Type(h) = observation {
            assert_eq!(h.status, EpistemicStatus::Derived);
            assert!(
                h.subject.path.is_empty(),
                "a canonical type is not file-scoped"
            );
        }
    }
    let types = io
        .obligations
        .iter()
        .find(|o| o.dimension == SemanticDimension::Type)
        .unwrap();
    assert_eq!(types.observation_ids.len(), claims.len());
    fs::remove_dir_all(&dir).unwrap();
}

/// G117 (NA-CONCURRENCY-RESOLVED): a path call resolved to a std path the declared concurrency
/// table names is a DERIVED concurrency site of its caller; an undeclared std path, a workspace
/// function merely named `spawn`, and a method call inside a closure are not.
#[test]
fn resolved_standard_library_paths_are_concurrency_sites_of_the_caller() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "atlas-g117-concurrency-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(dir.join("core/src")).unwrap();
    fs::write(dir.join("core/Cargo.toml"), "[package]\nname = \"core\"\n").unwrap();
    fs::write(dir.join("core/src/lib.rs"), "pub mod work;\n").unwrap();
    fs::write(
        dir.join("core/src/work.rs"),
        "use std::sync::mpsc;\nuse std::thread;\npub fn run() {\n    thread::scope(|s| {\n        s.spawn(|| {});\n    });\n    std::thread::spawn(|| {});\n    let (_tx, _rx) = mpsc::channel::<u8>();\n    thread::sleep(std::time::Duration::from_millis(0));\n}\nmod pool {\n    pub fn spawn() {}\n}\npub fn fake() {\n    pool::spawn();\n}\n",
    )
    .unwrap();
    let inventory = InventoryReport::new(
        dir.to_string_lossy().into_owned(),
        vec![
            artifact("core/Cargo.toml", "toml"),
            artifact("core/src/lib.rs", "rust"),
            artifact("core/src/work.rs", "rust"),
        ],
    );
    let batches = extract_semantics(&inventory, RepositoryId::new("atlas-studio"), revision());
    let resolution = resolve_rust_path_calls(&inventory, &batches);
    let work = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/work.rs")
        .unwrap();
    let sites: Vec<(usize, &str)> = work
        .observations
        .iter()
        .filter_map(|o| match o {
            SemanticObservation::Concurrency(h) => {
                Some((h.subject.span.line, h.subject.kind.as_str()))
            }
            _ => None,
        })
        .collect();
    // thread::scope, std::thread::spawn, mpsc::channel; never thread::sleep (undeclared),
    // pool::spawn (a workspace function) or s.spawn (a method call inside a closure).
    assert_eq!(
        sites,
        [(4, "THREAD_SCOPE"), (7, "SPAWN"), (8, "CHANNEL_CREATE")]
    );
    let run = batches
        .iter()
        .flat_map(|b| &b.observations)
        .find_map(|o| match o {
            SemanticObservation::FunctionIdentity(h) if h.subject.symbol.name == "run" => {
                Some(h.record_id.clone())
            }
            _ => None,
        })
        .unwrap();
    for observation in &work.observations {
        if let SemanticObservation::Concurrency(h) = observation {
            assert_eq!(h.subject.function, run, "the caller owns the site");
            assert_eq!(h.status, EpistemicStatus::Derived);
            assert_eq!(h.extractor.id, RUST_PATH_RESOLUTION_ID);
        }
    }
    let obligation = work
        .obligations
        .iter()
        .find(|o| o.dimension == SemanticDimension::Concurrency)
        .expect("the engine is asked for CONCURRENCY");
    assert_eq!(obligation.status, EpistemicStatus::Unknown);
    assert_eq!(obligation.observation_ids.len(), 3);
    fs::remove_dir_all(&dir).unwrap();
}

/// G125 (NA-PERSISTENCE-RESOLVED): a path call resolved to a std path the declared persistence
/// table names is a DERIVED persistence site of its caller -- the resolved API is the evidence, the
/// place is not claimed -- and nothing else is: an opened file, a workspace function spelled like
/// std, or a method call.
#[test]
fn resolved_standard_library_paths_are_persistence_sites_of_the_caller() {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "atlas-g125-persistence-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(dir.join("core/src")).unwrap();
    fs::write(dir.join("core/Cargo.toml"), "[package]\nname = \"core\"\n").unwrap();
    fs::write(dir.join("core/src/lib.rs"), "pub mod store;\n").unwrap();
    fs::write(
        dir.join("core/src/store.rs"),
        "use std::fs;\npub fn keep() {\n    fs::write(\"a\", \"b\");\n    let _ = std::fs::read_to_string(\"a\");\n    let f = fs::File::open(\"a\");\n    local::write();\n    f.sync_all();\n}\nmod local {\n    pub fn write() {}\n}\n",
    )
    .unwrap();
    let inventory = InventoryReport::new(
        dir.to_string_lossy().into_owned(),
        vec![
            artifact("core/Cargo.toml", "toml"),
            artifact("core/src/lib.rs", "rust"),
            artifact("core/src/store.rs", "rust"),
        ],
    );
    let batches = extract_semantics(&inventory, RepositoryId::new("atlas-studio"), revision());
    let resolution = resolve_rust_path_calls(&inventory, &batches);
    let store = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/store.rs")
        .unwrap();
    let sites: Vec<(usize, &str)> = store
        .observations
        .iter()
        .filter_map(|o| match o {
            SemanticObservation::Persistence(h) => {
                assert_eq!(h.status, EpistemicStatus::Derived);
                assert_eq!(h.extractor.id, RUST_PATH_RESOLUTION_ID);
                assert_eq!(
                    h.subject.resolution,
                    atlas_core::PersistenceResolution::Resolved
                );
                assert_eq!(h.subject.place, atlas_core::PlaceRef::Unresolved);
                Some((h.subject.span.line, h.subject.kind.as_str()))
            }
            _ => None,
        })
        .collect();
    assert_eq!(sites, [(3, "DURABLE_WRITE"), (4, "DURABLE_READ")]);
    let obligation = store
        .obligations
        .iter()
        .find(|o| o.dimension == SemanticDimension::Persistence)
        .expect("the engine accounts for PERSISTENCE");
    assert_eq!(
        obligation.status,
        EpistemicStatus::Unknown,
        "method calls stay outside"
    );
    fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn resolved_acquisitions_and_let_bound_releases_are_resource_records() {
    // G157: an acquisition is DERIVED at the resolved call; a holder never moved is released at
    // its block's end (INFERRED, syntactic move check), a resolved `drop` statement releases it
    // there (DERIVED); a moved holder and a temporary guard have no release claimed; every
    // release names the acquisition it gives back.
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!(
        "atlas-g157-resource-{}-{nonce}",
        std::process::id()
    ));
    fs::create_dir_all(dir.join("core/src")).unwrap();
    fs::write(dir.join("core/Cargo.toml"), "[package]\nname = \"core\"\n").unwrap();
    fs::write(dir.join("core/src/lib.rs"), "pub mod io;\n").unwrap();
    fs::write(
        dir.join("core/src/io.rs"),
        "use std::fs::File;\nuse std::sync::Mutex;\nfn keep(_f: File) {}\npub fn read(p: &str, m: &Mutex<u8>) -> std::io::Result<()> {\n    let file = File::open(p)?;\n    file.metadata()?;\n    let guard = m.lock().unwrap();\n    drop(guard);\n    let kept = File::open(p)?;\n    keep(kept);\n    let _v = *m.lock().unwrap();\n    Ok(())\n}\n",
    )
    .unwrap();
    let inventory = InventoryReport::new(
        dir.to_string_lossy().into_owned(),
        vec![
            artifact("core/Cargo.toml", "toml"),
            artifact("core/src/lib.rs", "rust"),
            artifact("core/src/io.rs", "rust"),
        ],
    );
    let batches = extract_semantics(&inventory, RepositoryId::new("atlas-studio"), revision());
    let resolution = resolve_rust_path_calls(&inventory, &batches);
    let io = resolution
        .iter()
        .find(|b| b.artifact.as_str() == "artifact:core/src/io.rs")
        .unwrap();
    let sites: Vec<(usize, String, EpistemicStatus, Option<usize>)> = io
        .observations
        .iter()
        .filter_map(|o| match o {
            SemanticObservation::Resource(h) => {
                assert_eq!(h.extractor.id, RUST_PATH_RESOLUTION_ID);
                assert!(h.subject.is_well_formed());
                let kind = match h.subject.release {
                    Some(release) => format!(
                        "{} {} {} {}",
                        h.subject.operation.as_str(),
                        h.subject.kind.as_str(),
                        release.as_str(),
                        h.subject.holder
                    ),
                    None => format!(
                        "{} {}",
                        h.subject.operation.as_str(),
                        h.subject.kind.as_str()
                    ),
                };
                Some((
                    h.subject.span.line,
                    kind,
                    h.status,
                    h.subject.acquired_at.as_ref().map(|a| a.line),
                ))
            }
            _ => None,
        })
        .collect();
    let derived = EpistemicStatus::Derived;
    assert_eq!(
        sites,
        [
            (5, "ACQUIRE FILE".to_owned(), derived, None),
            (7, "ACQUIRE LOCK_GUARD".to_owned(), derived, None),
            (9, "ACQUIRE FILE".to_owned(), derived, None),
            (11, "ACQUIRE LOCK_GUARD".to_owned(), derived, None),
            (
                13,
                "RELEASE FILE SCOPE_END file".to_owned(),
                EpistemicStatus::Inferred,
                Some(5)
            ),
            (
                8,
                "RELEASE LOCK_GUARD EXPLICIT_DROP guard".to_owned(),
                derived,
                Some(7)
            ),
        ]
    );
    let obligation = io
        .obligations
        .iter()
        .find(|o| o.dimension == SemanticDimension::Resource)
        .expect("the engine accounts for RESOURCE");
    assert_eq!(
        obligation.status,
        EpistemicStatus::Unknown,
        "temporaries and moved holders stay outside"
    );
    fs::remove_dir_all(&dir).unwrap();
}
