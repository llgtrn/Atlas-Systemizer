//! Donor working-set measurement and gating (ADR 0021): measures the filesystem and every local
//! donor directory, checks storage integrity against the recorded `storage_state`s, and decides
//! admissions with `atlas_core::donor`.

use atlas_core::donor::{
    AdmissionDecision, DiskMeasurement, Pressure, StoragePolicy, StorageRecord, StorageState,
    StorageViolation, WorkingSetEntry, check_integrity, decide_admission,
};
pub use atlas_core::donor::{AdmissionRequest, MaterializationMode};
use serde::{Deserialize, Serialize};
use std::{
    fs, io,
    path::{Path, PathBuf},
    process::Command,
};

/// Legacy tracked donor trees (pre-ADR 0021; drained by extinction, never extended).
pub const LEGACY_DONOR_ROOT: &str = ".atlas/temporary/donors";
/// Where every new materialization goes: untracked, git-ignored scratch.
pub const SCRATCH_DONOR_ROOT: &str = ".atlas/.cache/donors";
pub const WORKING_SET_FILE: &str = ".atlas/roadmap/DONOR-WORKING-SET.toml";

/// Measures the filesystem holding `path` with POSIX `df -P -k`. Capacity is used + available,
/// the basis of `df`'s own Use%, so reserved blocks and per-session allowances do not inflate it.
pub fn measure_disk(path: &Path) -> io::Result<DiskMeasurement> {
    let output = Command::new("df").arg("-P").arg("-k").arg(path).output()?;
    if !output.status.success() {
        return Err(io::Error::other(format!(
            "df failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    parse_df(&String::from_utf8_lossy(&output.stdout))
}

fn parse_df(text: &str) -> io::Result<DiskMeasurement> {
    let invalid = |why: &str| io::Error::new(io::ErrorKind::InvalidData, format!("df: {why}"));
    let line = text.lines().nth(1).ok_or_else(|| invalid("no data line"))?;
    // Filesystem 1024-blocks Used Available Capacity Mounted-on; the filesystem name may contain
    // spaces, so count fields from the right.
    let fields: Vec<&str> = line.split_whitespace().collect();
    if fields.len() < 6 {
        return Err(invalid("too few fields"));
    }
    let n = fields.len();
    let kib = |field: &str| -> io::Result<u64> {
        field
            .parse::<u64>()
            .map_err(|_| invalid("non-numeric size"))?
            .checked_mul(1024)
            .ok_or_else(|| invalid("size overflow"))
    };
    let used = kib(fields[n - 4])?;
    let available = kib(fields[n - 3])?;
    Ok(DiskMeasurement {
        capacity_bytes: used.saturating_add(available),
        available_bytes: available,
    })
}

/// Apparent size of every regular file under `path` (symlinks are not followed).
pub fn directory_bytes(path: &Path) -> io::Result<u64> {
    let mut total = 0u64;
    let mut stack = vec![path.to_path_buf()];
    while let Some(dir) = stack.pop() {
        for entry in fs::read_dir(&dir)? {
            let entry = entry?;
            let metadata = entry.path().symlink_metadata()?;
            if metadata.is_dir() {
                stack.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
            }
        }
    }
    Ok(total)
}

/// One donor-corpus record's storage fields and every location its source may occupy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct DonorStorage {
    pub id: String,
    pub state: StorageState,
    pub paths: Vec<String>,
}

/// Reads `storage_state` for every `[[donor]]` in `donor-corpus.toml`; locations are the legacy
/// root, the scratch root, and the provenance record's own `clone_path`.
pub fn load_donor_storage(root: &Path) -> io::Result<Vec<DonorStorage>> {
    let text = fs::read_to_string(root.join(".atlas/references/donor-corpus.toml"))?;
    let field = |block: &str, name: &str| {
        block.lines().find_map(|line| {
            let rest = line.trim().strip_prefix(name)?.strip_prefix(" = \"")?;
            Some(rest[..rest.find('"')?].to_owned())
        })
    };
    let mut donors = Vec::new();
    for block in text.split("[[donor]]").skip(1) {
        let invalid = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
        let id = field(block, "id").ok_or_else(|| invalid("donor without id".into()))?;
        let state_text = field(block, "storage_state")
            .ok_or_else(|| invalid(format!("donor `{id}` has no storage_state")))?;
        let state = StorageState::parse(&state_text).ok_or_else(|| {
            invalid(format!(
                "donor `{id}`: unknown storage_state `{state_text}`"
            ))
        })?;
        let mut paths = vec![
            format!("{LEGACY_DONOR_ROOT}/{id}"),
            format!("{SCRATCH_DONOR_ROOT}/{id}"),
        ];
        let provenance = root.join(format!(".atlas/provenance/donors/{id}.json"));
        if let Ok(text) = fs::read_to_string(provenance)
            && let Ok(value) = serde_json::from_str::<serde_json::Value>(&text)
            && let Some(clone_path) = value.get("clone_path").and_then(|v| v.as_str())
            && !paths.iter().any(|p| p == clone_path)
        {
            paths.push(clone_path.to_owned());
        }
        donors.push(DonorStorage { id, state, paths });
    }
    Ok(donors)
}

/// A local donor directory known to violate storage integrity whose remedy is recorded as
/// blocked (e.g. deletion awaiting user authorization). Recorded, never silently accepted.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RecordedBlocker {
    pub directory: String,
    pub classification: String,
    pub remedy: String,
}

/// The configured policy and recorded blockers from `DONOR-WORKING-SET.toml`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkingSetConfig {
    pub policy: StoragePolicy,
    pub blockers: Vec<RecordedBlocker>,
}

pub fn load_working_set_config(root: &Path) -> io::Result<WorkingSetConfig> {
    let text = fs::read_to_string(root.join(WORKING_SET_FILE))?;
    parse_working_set_config(&text)
}

fn parse_working_set_config(text: &str) -> io::Result<WorkingSetConfig> {
    let invalid = |why: String| io::Error::new(io::ErrorKind::InvalidData, why);
    let mut section = String::new();
    let mut numbers = std::collections::BTreeMap::new();
    let mut blockers: Vec<RecordedBlocker> = Vec::new();
    for line in text.lines().map(str::trim) {
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            section = line.to_owned();
            if section == "[[unadmitted_checkout]]" {
                blockers.push(RecordedBlocker {
                    directory: String::new(),
                    classification: String::new(),
                    remedy: String::new(),
                });
            }
            continue;
        }
        let Some((key, value)) = line.split_once(" = ") else {
            continue;
        };
        let unquoted = value.trim().trim_matches('"').to_owned();
        match section.as_str() {
            "[policy]" => {
                let number: u64 = value
                    .trim()
                    .replace('_', "")
                    .parse()
                    .map_err(|_| invalid(format!("policy.{key} is not an integer")))?;
                numbers.insert(key.to_owned(), number);
            }
            "[[unadmitted_checkout]]" => {
                let blocker = blockers.last_mut().expect("pushed on header");
                match key {
                    "directory" => blocker.directory = unquoted,
                    "classification" => blocker.classification = unquoted,
                    "remedy" => blocker.remedy = unquoted,
                    _ => {}
                }
            }
            _ => {}
        }
    }
    let get = |key: &str| {
        numbers
            .get(key)
            .copied()
            .ok_or_else(|| invalid(format!("policy.{key} missing")))
    };
    let policy = StoragePolicy {
        healthy_min_free_permille: get("healthy_min_free_permille")?,
        pressure_min_free_permille: get("pressure_min_free_permille")?,
        high_pressure_min_free_permille: get("high_pressure_min_free_permille")?,
        build_headroom_permille: get("build_headroom_permille")?,
        build_headroom_min_bytes: get("build_headroom_min_bytes")?,
        safety_reserve_permille: get("safety_reserve_permille")?,
        safety_reserve_min_bytes: get("safety_reserve_min_bytes")?,
        max_working_set_permille: get("max_working_set_permille")?,
        large_donor_bytes: get("large_donor_bytes")?,
    };
    policy.validate().map_err(invalid)?;
    if blockers
        .iter()
        .any(|b| b.directory.is_empty() || b.remedy.is_empty())
    {
        return Err(invalid(
            "an unadmitted_checkout lacks directory or remedy".into(),
        ));
    }
    Ok(WorkingSetConfig { policy, blockers })
}

/// What `atlas-systemizer donors working-set` emits.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WorkingSetReport {
    pub schema: String,
    pub disk: DiskMeasurement,
    pub free_permille: u64,
    pub pressure: Pressure,
    pub policy: StoragePolicy,
    pub donor_budget_bytes: u64,
    pub working_set_cap_bytes: u64,
    /// Every donor whose source is local, with its measured apparent size.
    pub working_set: Vec<WorkingSetEntry>,
    pub working_set_bytes: u64,
    /// Local donor directories owned by no source-holding record, with their sizes.
    pub unowned_bytes: u64,
    /// Integrity violations whose remedy is recorded as blocked.
    pub recorded_violations: Vec<StorageViolation>,
    /// Integrity violations nobody has recorded: always a failure.
    pub unrecorded_violations: Vec<StorageViolation>,
    pub admission: Option<AdmissionDecision>,
}

fn local_directories(root: &Path) -> io::Result<Vec<String>> {
    let mut directories = Vec::new();
    for base in [LEGACY_DONOR_ROOT, SCRATCH_DONOR_ROOT] {
        let Ok(entries) = fs::read_dir(root.join(base)) else {
            continue;
        };
        for entry in entries {
            let entry = entry?;
            if entry.path().symlink_metadata()?.is_dir() {
                directories.push(format!("{base}/{}", entry.file_name().to_string_lossy()));
            }
        }
    }
    directories.sort();
    Ok(directories)
}

/// G152 (ADR 0067): the source paths the FULL_OSS_REPLAY ledger records MATERIALIZED -- a
/// checkout there is the replay lane's, held under its one-donor window, not an orphan.
fn replay_materialized_paths(root: &Path) -> Vec<String> {
    let text =
        fs::read_to_string(root.join(".atlas/roadmap/FULL-OSS-REPLAY.toml")).unwrap_or_default();
    text.split("\n[[repository]]\n")
        .filter(|block| block.contains("\nreplay_status = \"MATERIALIZED\""))
        .filter_map(|block| {
            let line = block.lines().find(|l| l.starts_with("source_path = "))?;
            Some(
                line.trim_start_matches("source_path = ")
                    .trim_matches('"')
                    .to_owned(),
            )
        })
        .collect()
}

/// Measures the disk and the working set, checks integrity, and (given a request) decides its
/// admission. `measure_sizes = false` skips the directory walks (sizes read as 0).
pub fn working_set_report(
    root: &Path,
    request: Option<&AdmissionRequest>,
    measure_sizes: bool,
) -> io::Result<WorkingSetReport> {
    let config = load_working_set_config(root)?;
    let donors = load_donor_storage(root)?;
    let disk = measure_disk(root)?;
    let size = |path: &Path| -> io::Result<u64> {
        if measure_sizes {
            directory_bytes(path)
        } else {
            Ok(0)
        }
    };
    let mut records = Vec::new();
    let mut working_set = Vec::new();
    for donor in &donors {
        let present: Vec<PathBuf> = donor
            .paths
            .iter()
            .map(|p| root.join(p))
            .filter(|p| p.exists())
            .collect();
        records.push(StorageRecord {
            donor: donor.id.clone(),
            state: donor.state,
            source_present: !present.is_empty(),
        });
        if !present.is_empty() || donor.state.source_present() != Some(false) {
            let mut bytes = 0u64;
            for path in &present {
                bytes = bytes.saturating_add(size(path)?);
            }
            working_set.push(WorkingSetEntry {
                donor: donor.id.clone(),
                state: donor.state,
                bytes,
            });
        }
    }
    let directories = local_directories(root)?;
    let owner_of = |directory: &str| -> Option<String> {
        donors
            .iter()
            .find(|d| {
                d.paths
                    .iter()
                    .any(|p| p == directory || p.starts_with(&format!("{directory}/")))
            })
            .map(|d| d.id.clone())
    };
    // A grouping directory (e.g. `security/`) is owned when any donor inside it holds source.
    let owner_holding = |directory: &str| -> Option<String> {
        donors
            .iter()
            .filter(|d| d.state.source_present() != Some(false))
            .find(|d| {
                d.paths
                    .iter()
                    .any(|p| p == directory || p.starts_with(&format!("{directory}/")))
            })
            .map(|d| d.id.clone())
            .or_else(|| owner_of(directory))
    };
    let violations = check_integrity(&records, &directories, owner_holding);
    let replay_materialized = replay_materialized_paths(root);
    let mut unowned_bytes = 0u64;
    let (mut recorded_violations, mut unrecorded_violations) = (Vec::new(), Vec::new());
    for violation in violations {
        let recorded = match &violation {
            StorageViolation::UnownedCheckout { directory } => {
                unowned_bytes = unowned_bytes.saturating_add(size(&root.join(directory))?);
                config
                    .blockers
                    .iter()
                    .any(|b| format!("{LEGACY_DONOR_ROOT}/{}", b.directory) == *directory)
                    || replay_materialized.contains(directory)
            }
            _ => false,
        };
        if recorded {
            recorded_violations.push(violation);
        } else {
            unrecorded_violations.push(violation);
        }
    }
    let admission = request.map(|r| decide_admission(&config.policy, disk, &working_set, r));
    let working_set_bytes = working_set.iter().map(|e| e.bytes).sum();
    Ok(WorkingSetReport {
        schema: "atlas.donor-working-set-report.v1".into(),
        free_permille: disk.free_permille(),
        pressure: config.policy.pressure(disk),
        donor_budget_bytes: config.policy.donor_budget(disk),
        working_set_cap_bytes: config.policy.max_working_set(disk),
        disk,
        policy: config.policy,
        working_set,
        working_set_bytes,
        unowned_bytes,
        recorded_violations,
        unrecorded_violations,
        admission,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn workspace_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .to_path_buf()
    }

    #[test]
    fn df_output_is_parsed_from_the_right_and_capacity_is_used_plus_available() {
        let text = "Filesystem     1024-blocks      Used Available Capacity Mounted on\n\
                    /dev/my disk     264241152  30408704   9542656      77% /\n";
        let disk = parse_df(text).unwrap();
        assert_eq!(disk.available_bytes, 9_542_656 * 1024);
        assert_eq!(disk.capacity_bytes, (30_408_704 + 9_542_656) * 1024);
        assert_eq!(disk.free_permille(), 238);
        assert!(parse_df("Filesystem\n").is_err());
        assert!(parse_df("h\n/dev/x 1 a b 1% /\n").is_err());
    }

    #[test]
    fn the_filesystem_is_measurable_here() {
        let disk = measure_disk(&workspace_root()).unwrap();
        assert!(disk.capacity_bytes >= disk.available_bytes && disk.capacity_bytes > 0);
    }

    #[test]
    fn the_recorded_policy_is_valid_and_every_blocker_has_a_remedy() {
        let config = load_working_set_config(&workspace_root()).unwrap();
        assert!(config.policy.validate().is_ok());
        assert!(!config.blockers.is_empty());
        let broken = "[policy]\nhealthy_min_free_permille = 100\n";
        assert!(parse_working_set_config(broken).is_err());
    }

    /// Storage integrity of the real repository: every record agrees with the disk and every
    /// local donor directory is owned or a recorded blocker. An unrecorded violation (a new
    /// orphan checkout, an EXTINCT donor whose source reappeared, a MATERIALIZED donor whose
    /// source vanished) fails here.
    #[test]
    fn repository_donor_storage_has_no_unrecorded_violation() {
        let _census = crate::whole_repo_census_lock();
        let root = workspace_root();
        let request = AdmissionRequest {
            donor: "probe".into(),
            mode: MaterializationMode::RemoteMetadata,
            estimated_source_bytes: 0,
            estimated_build_bytes: 0,
        };
        let report = working_set_report(&root, Some(&request), false).unwrap();
        assert!(
            report.unrecorded_violations.is_empty(),
            "{:#?}",
            report.unrecorded_violations
        );
        assert!(
            report.admission.unwrap().admitted(),
            "remote discovery is free"
        );
        // Every recorded blocker still exists as a violation: a resolved one must be removed from
        // the record (the list can only shrink truthfully).
        let config = load_working_set_config(&root).unwrap();
        for blocker in &config.blockers {
            assert!(
                report.recorded_violations.iter().any(|v| matches!(
                    v,
                    StorageViolation::UnownedCheckout { directory }
                        if *directory == format!("{LEGACY_DONOR_ROOT}/{}", blocker.directory)
                )),
                "blocker `{}` no longer violates; remove it from {WORKING_SET_FILE}",
                blocker.directory
            );
        }
        let mut deleted: Vec<_> = load_donor_storage(&root)
            .unwrap()
            .into_iter()
            .filter(|d| d.state == StorageState::SourceDeleted)
            .map(|d| d.id)
            .collect();
        deleted.sort();
        assert_eq!(
            deleted,
            [
                "agentir",
                "arrow",
                "ast-grep",
                "blake3",
                "buck2",
                "c2rust",
                "capnproto",
                "clef",
                "composer",
                "containers-image",
                "crubit",
                "datafrog",
                "differential-dataflow",
                "duumbi",
                "egglog",
                "flatbuffers",
                "glean",
                "iris",
                "joern",
                "kani",
                "kythe",
                "ladybird",
                "llvm-project",
                "miri",
                "mlir",
                "mold",
                "object",
                "openrewrite",
                "podman",
                "regalloc2",
                "rkyv",
                "rust",
                "rust-analyzer",
                "salsa",
                "scip",
                "semgrep",
                "sigil-lang",
                "souffle",
                "sourcetrail",
                "tree-sitter",
                "verus",
                "wasm-component-model",
                "wasm-spec",
                "wasm-tools",
                "wasmtime",
                "xdsl",
                "xyflow",
                "zed",
                "zstd"
            ]
        );
    }

    #[test]
    fn storage_state_serde_names_agree_with_the_recorded_names() {
        for state in StorageState::ALL {
            let json = serde_json::to_string(&state).unwrap();
            assert_eq!(json, format!("\"{}\"", state.as_str()));
        }
    }
}
