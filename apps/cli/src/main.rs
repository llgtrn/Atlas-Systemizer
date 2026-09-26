use std::{env, fs, path::PathBuf, process::ExitCode};

/// `Ok(None)` when `name` is not present at all; `Ok(Some(v))` when present with a following
/// value; `Err` when `name` is present but has no following argument (e.g. it is the last token,
/// or immediately followed by another flag) -- a real shell-scripting failure mode (an unset/empty
/// variable dropped by word-splitting: `--base-sha "$BASE_SHA"` with `$BASE_SHA` unset becomes
/// `--base-sha` with nothing after it), never conflated with the flag being absent on purpose.
/// Before this fix, a genuinely optional flag like `--base-sha` silently fell back to `None` in
/// either case, defeating `EXACT_BASE_SHA_REQUIRED` on malformed input instead of failing loud.
fn value(args: &[String], name: &str) -> Result<Option<String>, String> {
    match args.iter().position(|x| x == name) {
        None => Ok(None),
        Some(i) => match args.get(i + 1) {
            Some(v) => Ok(Some(v.clone())),
            None => Err(format!("{name} requires a value")),
        },
    }
}

fn json<T: serde::Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string_pretty(value).map_err(|e| e.to_string())
}

/// Writes `text` to `out`, creating its parent directory first. Shared by every subcommand that
/// takes `--out` so the path-context fix below applies uniformly instead of needing to be
/// remembered at each of the four call sites separately -- the exact failure mode this closes
/// (`io::Error::to_string()` naming no path) is the same class already fixed for `--root` in
/// every subcommand's `runtime::*` call, just for the output path instead of the input one.
fn write_report_to_out(out: &str, text: &str) -> Result<(), String> {
    let out_path = PathBuf::from(out);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("{out}: {e}"))?;
    }
    fs::write(&out_path, text).map_err(|e| format!("{out}: {e}"))
}

fn run(args: &[String]) -> Result<(), String> {
    match args {
        [cmd, rest @ ..] if cmd == "contract" => {
            if value(rest, "--format")?.as_deref() != Some("json") {
                return Err("contract requires --format json".into());
            }
            println!("{}", json(&runtime::contract())?);
        }
        [cmd, sub, rest @ ..] if cmd == "docs" && sub == "audit" => {
            let root = value(rest, "--root")?.ok_or("docs audit requires --root")?;
            let report = runtime::docs_audit(&root).map_err(|e| format!("{root}: {e}"))?;
            println!("{}", json(&report)?);
            if !report.gate_ready {
                return Err("DOCS_GATE_NOT_READY".into());
            }
        }
        [cmd, sub, rest @ ..] if cmd == "code" && sub == "analyze" => {
            let root = value(rest, "--root")?.ok_or("code analyze requires --root")?;
            let report = runtime::code_analyze(&root).map_err(|e| format!("{root}: {e}"))?;
            println!("{}", json(&report)?);
        }
        [cmd, rest @ ..] if cmd == "parse" => {
            let root = value(rest, "--root")?.ok_or("parse requires --root")?;
            let programs = runtime::parse(&root).map_err(|e| format!("{root}: {e}"))?;
            println!(
                "{}",
                json(&serde_json::json!({
                    "schema": "atlas.adl.parse-report.v1",
                    "sources_total": programs.len(),
                    "programs": programs
                }))?
            );
        }
        [cmd, rest @ ..] if cmd == "check" => {
            let root = value(rest, "--root")?.ok_or("check requires --root")?;
            let report = runtime::check(&root).map_err(|e| format!("{root}: {e}"))?;
            let text = json(&report)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            if !report.diagnostics.is_empty()
                || report
                    .constraint_results
                    .iter()
                    .any(|result| !result.passed)
            {
                return Err("ADL_CHECK_NOT_READY".into());
            }
        }
        [cmd, rest @ ..] if cmd == "graph" => {
            let root = value(rest, "--root")?.ok_or("graph requires --root")?;
            let report = runtime::graph(&root).map_err(|e| format!("{root}: {e}"))?;
            let text = json(&report)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
        }
        [cmd, rest @ ..] if cmd == "systemize" => {
            let root = value(rest, "--root")?.ok_or("systemize requires --root")?;
            let out = value(rest, "--out")?.ok_or("systemize requires --out")?;
            // `--previous <earlier systemize --out report>`: diff this run's inventory against
            // that report's `inventory` (ADR 0006) and emit `inventory_delta`.
            let previous = value(rest, "--previous")?
                .map(|path| {
                    runtime::read_previous_inventory(&path).map_err(|e| format!("{path}: {e}"))
                })
                .transpose()?;
            // `--cache <dir>`: reuse per-artifact semantic extraction across runs (ADR 0008).
            let mut cache = value(rest, "--cache")?
                .map(|dir| {
                    runtime::census::extraction::ExtractionCache::open(&dir)
                        .map_err(|e| format!("{dir}: {e}"))
                })
                .transpose()?;
            let report = runtime::systemize_with(&root, previous.as_ref(), cache.as_mut())
                .map_err(|e| format!("{root}: {e}"))?;
            let text = json(&report)? + "\n";
            write_report_to_out(&out, &text)?;
            print!("{text}");
            // Every sibling subcommand whose report carries a readiness gate enforces it here
            // (`docs audit` -> DOCS_GATE_NOT_READY, `check` -> ADL_CHECK_NOT_READY, `work prepare`
            // -> WORK_PREPARE_NOT_ALLOWED) so a blocked repository makes the process exit non-zero,
            // not just print a report a caller must remember to re-parse. `systemize` carries the
            // single most consequential gate of all -- `coding_admission.allowed`, derived from
            // every blocker this pipeline can raise (REPO_GATE_NOT_READY, DOCS_GATE_NOT_READY,
            // ADL_DIAGNOSTICS_PRESENT, ADL_CONSTRAINT_VIOLATED, and every *_ACCOUNTING_NOT_CLOSED/
            // DEPENDENCY_CLOSURE_NOT_CLOSED coverage gap) -- yet this was the one handler that
            // silently dropped the check its three siblings all have: `.atlas/repo.toml`'s own
            // `compile` command invokes exactly this subcommand, so any orchestration step gating
            // on this process's exit code (rather than re-parsing the JSON body itself) previously
            // treated a blocked repository as a successful compile.
            if !report.coding_admission.allowed {
                return Err("CODING_ADMISSION_NOT_ALLOWED".into());
            }
        }
        [cmd, rest @ ..] if cmd == "physical" => {
            // Physical Engineering milestone 1 (ADR 0012): digital-only model of declared arms.
            let root = value(rest, "--root")?.ok_or("physical requires --root")?;
            let analysis =
                runtime::physical::analyze_root(&root).map_err(|e| format!("{root}: {e}"))?;
            let text = json(&analysis)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            let undecided = analysis
                .physical
                .findings
                .iter()
                .any(|f| !f.verdict.admits())
                || analysis
                    .physical
                    .requirements
                    .iter()
                    .any(|check| !check.verdict.admits());
            if undecided {
                return Err("PHYSICAL_REQUIREMENTS_NOT_SATISFIED".into());
            }
        }
        [cmd, rest @ ..] if cmd == "product" => {
            // Product Foundry (ADR 0023): declared products -> BOM, unit economics, requirements.
            // Every number carries its evidence basis; nothing here asserts market truth.
            let root = value(rest, "--root")?.ok_or("product requires --root")?;
            let analysis =
                runtime::product::analyze_root(&root).map_err(|e| format!("{root}: {e}"))?;
            let text = json(&analysis.product)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            let undecided = !analysis.product.findings.is_empty()
                || analysis
                    .product
                    .variants
                    .iter()
                    .flat_map(|v| &v.requirements)
                    .any(|check| !check.verdict.admits());
            if undecided {
                return Err("PRODUCT_REQUIREMENTS_NOT_SATISFIED".into());
            }
        }
        [cmd, rest @ ..] if cmd == "genome" => {
            // ADR 0018: abstract design mechanisms from authorized reference fixtures.
            let references: Vec<std::path::PathBuf> = rest
                .iter()
                .enumerate()
                .filter(|(_, arg)| *arg == "--fixture")
                .filter_map(|(i, _)| rest.get(i + 1).map(std::path::PathBuf::from))
                .collect();
            if references.is_empty() {
                return Err("genome requires at least one --fixture".into());
            }
            let refs: Vec<&std::path::Path> = references.iter().map(|p| p.as_path()).collect();
            let genome = runtime::visual::extract_genome(&refs).map_err(|e| e.to_string())?;
            let text = json(&genome)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
        }
        [cmd, sub, rest @ ..] if cmd == "census" && sub == "certificate" => {
            // ADR 0025: the CensusCertificate v2 of a root (two passes for the replay fixed
            // point). Exits CENSUS_NOT_CLOSED unless the state is CLOSED or SEALED.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            // ADR 0027: with --atlas, the container must package exactly this census; its
            // verified root identity then enters the certificate (unsealed: never SEALED).
            let certificate = match value(rest, "--atlas")? {
                Some(atlas) => runtime::atlas::certificate_with_atlas(&root, &atlas)
                    .map_err(|e| format!("{atlas}: {e}"))?,
                None => runtime::certificate::certificate(&root, 2)
                    .map_err(|e| format!("{root}: {e}"))?,
            };
            let text = json(&certificate)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            if certificate.state < runtime::certificate::CertificateState::Closed {
                return Err("CENSUS_NOT_CLOSED".into());
            }
        }
        [cmd, sub, rest @ ..] if cmd == "atlas" && sub == "pack" => {
            // ADR 0027: census -> validated semantic state -> unsealed .atlas census container,
            // verified by decoding before an atomic publish.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let out = value(rest, "--out")?.ok_or("atlas pack requires --out")?;
            let packed = runtime::atlas::pack(&root, &out).map_err(|e| format!("{root}: {e}"))?;
            println!("{}", json(&packed)?);
        }
        [cmd, sub, file, rest @ ..] if cmd == "atlas" && sub == "verify" => {
            // ADR 0027: the reader's full verification; with --root, the container must also
            // package that root's current census.
            let root = value(rest, "--root")?;
            let verified = runtime::atlas::verify(file, root.as_deref().map(std::path::Path::new))
                .map_err(|e| format!("{file}: {e}"))?;
            println!("{}", json(&verified)?);
        }
        [cmd, sub, rest @ ..] if cmd == "adl" && sub == "derive" => {
            // ADR 0026: census truth the authored ADL does not declare, as ADL text. `--check`
            // exits ADL_CENSUS_DRIFT when the committed census.adl differs from it.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let derived = runtime::derive_census_adl(&root).map_err(|e| format!("{root}: {e}"))?;
            if rest.iter().any(|arg| arg == "--check") {
                let path = std::path::Path::new(&root).join(runtime::CENSUS_ADL_PATH);
                let committed = fs::read_to_string(&path).unwrap_or_default();
                if committed != derived {
                    return Err(format!(
                        "ADL_CENSUS_DRIFT: {} differs from census truth; regenerate with \
                         `atlas-systemizer adl derive --out {}`",
                        path.display(),
                        runtime::CENSUS_ADL_PATH
                    ));
                }
            }
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &derived)?;
            }
            print!("{derived}");
        }
        [cmd, sub, rest @ ..] if cmd == "seal" && sub == "policy" => {
            // G149 (ADR 0065): the strict self-scope seal policy. `--check` validates the declared
            // policy (identity, totality, never-permitted kinds, HARD dimensions) and exits
            // SEAL_POLICY_INVALID otherwise.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            if rest.iter().any(|arg| arg == "--check") {
                let declared =
                    runtime::seal::declared_policy(&root).map_err(|e| format!("{root}: {e}"))?;
                let problems = runtime::seal::validate_policy(&declared);
                if !problems.is_empty() {
                    return Err(format!("SEAL_POLICY_INVALID: {}", problems.join("; ")));
                }
                println!("{}", json(&declared)?);
            } else {
                let text = json(&runtime::seal::self_scope_policy())? + "\n";
                match value(rest, "--out")? {
                    Some(out) => write_report_to_out(&out, &text)?,
                    None => print!("{text}"),
                }
            }
        }
        [cmd, sub, rest @ ..] if cmd == "seal" && sub == "evaluate" => {
            // G149: a certificate's scoped verdict under the declared seal policy; exits
            // SEAL_NOT_ELIGIBLE unless every blocker is permitted.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let certificate =
                value(rest, "--certificate")?.ok_or("seal evaluate requires --certificate")?;
            let policy = match value(rest, "--policy")? {
                Some(path) => {
                    runtime::seal::read_policy(&path).map_err(|e| format!("{path}: {e}"))?
                }
                None => {
                    runtime::seal::declared_policy(&root).map_err(|e| format!("{root}: {e}"))?
                }
            };
            let verdict = runtime::seal::evaluate(&certificate, &policy)
                .map_err(|e| format!("{certificate}: {e}"))?;
            let text = json(&verdict)? + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
            if verdict.verdict != runtime::seal::ScopeVerdict::Eligible {
                return Err(format!(
                    "SEAL_NOT_ELIGIBLE: {} blockers refused",
                    verdict.refused.len()
                ));
            }
        }
        [cmd, sub, rest @ ..] if cmd == "seal" && sub == "gate" => {
            // G161 (M8, ADR 0076): whether the verified container `--atlas` can be sealed under
            // the declared policy, joined with the verification report, the integrity report and
            // an optional SelectedDesign; exits SEAL_NOT_ELIGIBLE with every typed reason.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let atlas = value(rest, "--atlas")?.ok_or("seal gate requires --atlas")?;
            let verification =
                value(rest, "--verification")?.ok_or("seal gate requires --verification")?;
            let integrity = value(rest, "--integrity")?.ok_or("seal gate requires --integrity")?;
            let design = value(rest, "--design")?;
            let policy = match value(rest, "--policy")? {
                Some(path) => {
                    runtime::seal::read_policy(&path).map_err(|e| format!("{path}: {e}"))?
                }
                None => {
                    runtime::seal::declared_policy(&root).map_err(|e| format!("{root}: {e}"))?
                }
            };
            let eligibility = runtime::seal::gate_container(
                &atlas,
                &verification,
                &integrity,
                design.as_deref().map(std::path::Path::new),
                &policy,
            )
            .map_err(|e| format!("{atlas}: {e}"))?;
            let text = json(&eligibility)? + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
            if eligibility.verdict != runtime::seal::ScopeVerdict::Eligible {
                return Err(format!(
                    "SEAL_NOT_ELIGIBLE: {} reasons",
                    eligibility.reasons.len()
                ));
            }
        }
        [cmd, sub, rest @ ..] if cmd == "atlas" && sub == "seal" => {
            // G161 (M9): writes `--atlas` sealed by the ELIGIBLE decision `--eligibility` (as
            // `seal gate` wrote it) to `--out`; the writer re-checks the record binds it.
            let atlas = value(rest, "--atlas")?.ok_or("atlas seal requires --atlas")?;
            let path = value(rest, "--eligibility")?.ok_or("atlas seal requires --eligibility")?;
            let out = value(rest, "--out")?.ok_or("atlas seal requires --out")?;
            let eligibility: runtime::seal::SealEligibility = serde_json::from_str(
                &fs::read_to_string(&path).map_err(|e| format!("{path}: {e}"))?,
            )
            .map_err(|e| format!("{path}: {e}"))?;
            let root = runtime::seal::seal_container(&atlas, &eligibility, &out)
                .map_err(|e| format!("{atlas}: {e}"))?;
            println!(
                "{}",
                json(&serde_json::json!({ "path": out, "root_id": root }))?
            );
        }
        [cmd, sub, rest @ ..] if cmd == "weights" && sub == "census" => {
            // G163 (ADR 0078): the physical census of a SafeTensors weight container -- storage
            // facts and payload digests; semantic roles stay UNKNOWN.
            let artifact =
                value(rest, "--artifact")?.ok_or("weights census requires --artifact")?;
            let census =
                runtime::weights::census_file(&artifact).map_err(|e| format!("{artifact}: {e}"))?;
            let text = json(&census)? + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "weights" && sub == "construct" => {
            // G163: a SafeTensors container constructed mechanically from the census of
            // `--artifact`, its payload streamed and digest-verified, then censused again.
            let artifact =
                value(rest, "--artifact")?.ok_or("weights construct requires --artifact")?;
            let out = value(rest, "--out")?.ok_or("weights construct requires --out")?;
            let outcome = runtime::weights::construct_file(&artifact, &out)
                .map_err(|e| format!("{artifact}: {e}"))?;
            println!("{}", json(&outcome)?);
            if !outcome.content_preserved {
                return Err("WEIGHT_CONTENT_NOT_PRESERVED".into());
            }
        }
        [cmd, sub, rest @ ..] if cmd == "design" && sub == "roots" => {
            // G148: the FUNCTION_IDENTITY roots of a verified container named `--function`.
            let atlas = value(rest, "--atlas")?.ok_or("design roots requires --atlas")?;
            let name = value(rest, "--function")?.ok_or("design roots requires --function")?;
            let path = value(rest, "--path")?.unwrap_or_default();
            let roots = runtime::design::function_roots_in(&atlas, &name, &path)
                .map_err(|e| format!("{atlas}: {e}"))?;
            println!("{}", json(&roots)?);
        }
        [cmd, sub, rest @ ..] if cmd == "coverage" && sub == "levels" => {
            // G155 (ADR 0071): measured L0-L6 support per language and artifact class, from the
            // inventory, census and composed world model of `--root`.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let report =
                runtime::agent::support_levels(&root).map_err(|e| format!("{root}: {e}"))?;
            println!("{}", json(&report)?);
        }
        [cmd, sub, rest @ ..] if cmd == "self-reconstruct" && sub == "candidates" => {
            // G153 (ADR 0069): the core types Atlas could reconstruct, ranked from what the
            // world model knows (`--model`), constructible first.
            let path =
                value(rest, "--model")?.ok_or("self-reconstruct candidates requires --model")?;
            let model =
                runtime::agent::read_world_model(&path).map_err(|e| format!("{path}: {e}"))?;
            let limit = value(rest, "--limit")?
                .map_or(Ok(usize::MAX), |l| l.parse::<usize>())
                .map_err(|e| format!("--limit: {e}"))?;
            let all = runtime::self_reconstruction::candidates(&model);
            let constructible = all.iter().filter(|c| c.constructible).count();
            let out = serde_json::json!({
                "schema": runtime::self_reconstruction::CANDIDATES_SCHEMA,
                "revision": model.revision,
                "types": all.len(),
                "constructible": constructible,
                "candidates": all.into_iter().take(limit).collect::<Vec<_>>(),
            });
            println!("{}", json(&out)?);
        }
        [cmd, sub, rest @ ..] if cmd == "self-reconstruct" && sub == "roots" => {
            // G153: the design roots of a target (its SYMBOL and its methods), by what it is.
            let atlas = value(rest, "--atlas")?.ok_or("self-reconstruct roots requires --atlas")?;
            let path = value(rest, "--path")?.ok_or("self-reconstruct roots requires --path")?;
            let name = value(rest, "--type")?.ok_or("self-reconstruct roots requires --type")?;
            let (container, _) =
                runtime::design::read_container(&atlas).map_err(|e| format!("{atlas}: {e}"))?;
            let roots =
                runtime::self_reconstruction::target_roots(&container.typed_records, &path, &name);
            println!("{}", roots.join(","));
        }
        [cmd, sub, rest @ ..] if cmd == "self-reconstruct" && sub == "attempt" => {
            // G153 (ADR 0069): one SH1 shadow reconstruction of `--type` in `--path` from the
            // verified container `--atlas` over `--design` (and `--comparison`): the module, the
            // shadow and the report go to `--out-dir`. Exits RECONSTRUCTION_INVALID when the
            // module or the report breaks the construction input boundary.
            let atlas =
                value(rest, "--atlas")?.ok_or("self-reconstruct attempt requires --atlas")?;
            let path = value(rest, "--path")?.ok_or("self-reconstruct attempt requires --path")?;
            let name = value(rest, "--type")?.ok_or("self-reconstruct attempt requires --type")?;
            let design_path =
                value(rest, "--design")?.ok_or("self-reconstruct attempt requires --design")?;
            let out_dir =
                value(rest, "--out-dir")?.ok_or("self-reconstruct attempt requires --out-dir")?;
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let design = runtime::design::read_design(&design_path)
                .map_err(|e| format!("{design_path}: {e}"))?;
            let comparison = match value(rest, "--comparison")? {
                Some(p) => {
                    Some(runtime::design::read_comparison(&p).map_err(|e| format!("{p}: {e}"))?)
                }
                None => None,
            };
            let (container, container_root) =
                runtime::design::read_container(&atlas).map_err(|e| format!("{atlas}: {e}"))?;
            if design.parent_root != container_root {
                return Err(format!(
                    "RECONSTRUCTION_INVALID: the design is over {}, the container is {container_root}",
                    design.parent_root
                ));
            }
            let (module, emission, report) =
                runtime::self_reconstruction::attempt(&runtime::self_reconstruction::Attempt {
                    root: std::path::Path::new(&root),
                    container: &container,
                    container_root: &container_root,
                    path: &path,
                    type_name: &name,
                    design_id: &design.design_id,
                    design_state: design.state,
                    comparison_id: comparison.as_ref().map(|c| c.comparison_id.as_str()),
                })?;
            let violations = runtime::self_reconstruction::validate(&container, &module, &report);
            std::fs::create_dir_all(&out_dir).map_err(|e| format!("{out_dir}: {e}"))?;
            let write = |file: &str, text: String| {
                std::fs::write(format!("{out_dir}/{file}"), text)
                    .map_err(|e| format!("{out_dir}/{file}: {e}"))
            };
            write("module.json", json(&module)? + "\n")?;
            write("report.json", json(&report)? + "\n")?;
            write("shadow.rs.txt", emission.source.clone())?;
            println!(
                "{}",
                json(&serde_json::json!({
                    "verdict": report.verdict,
                    "emitted": emission.emitted,
                    "omitted": emission.omitted,
                    "gaps": report.gaps.len(),
                    "checks": report.checks.len(),
                    "violations": violations,
                }))?
            );
            if !violations.is_empty() {
                return Err("RECONSTRUCTION_INVALID".into());
            }
        }
        [cmd, sub, rest @ ..] if cmd == "design" && sub == "propose" => {
            // G148 (ADR 0064): a VALIDATED SelectedDesign over a verified census container, its
            // roots resolving there and its report admitting the container's candidate. Exits
            // DESIGN_REJECTED otherwise. Proposing never selects.
            let atlas = value(rest, "--atlas")?.ok_or("design propose requires --atlas")?;
            let report_path = value(rest, "--report")?.ok_or("design propose requires --report")?;
            let report = runtime::design::read_report(&report_path)
                .map_err(|e| format!("{report_path}: {e}"))?;
            let mut roots = Vec::new();
            for (i, arg) in rest.iter().enumerate() {
                if arg == "--root" {
                    let spec = rest
                        .get(i + 1)
                        .ok_or("--root requires DIMENSION:RECORD_ID")?;
                    roots.push(runtime::design::parse_root(spec)?);
                }
            }
            let proposal = runtime::design::Proposal {
                roots,
                bindings: Vec::new(),
                scope: value(rest, "--scope")?.ok_or("design propose requires --scope")?,
                target_kind: value(rest, "--target-kind")?
                    .ok_or("design propose requires --target-kind")?,
                variant: value(rest, "--variant")?.unwrap_or_else(|| "default".into()),
                rationale: value(rest, "--rationale")?.unwrap_or_default(),
                evidence_ref: report_path.clone(),
            };
            let (design, violations) = runtime::design::propose(&atlas, &report, proposal)
                .map_err(|e| format!("{atlas}: {e}"))?;
            let text = json(&design)? + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
            if !violations.is_empty() {
                return Err(format!("DESIGN_REJECTED: {}", json(&violations)?));
            }
        }
        [cmd, sub, rest @ ..] if cmd == "design" && sub == "candidates" => {
            // G150 (ADR 0066): candidate designs at one coordinate, one per `--candidate` (its
            // roots, comma-separated DIMENSION:RECORD_ID), each naming all of them as its
            // candidate set; written to `--out-dir` as <design id>.json. Never selects.
            let atlas = value(rest, "--atlas")?.ok_or("design candidates requires --atlas")?;
            let report_path =
                value(rest, "--report")?.ok_or("design candidates requires --report")?;
            let out_dir =
                value(rest, "--out-dir")?.ok_or("design candidates requires --out-dir")?;
            let report = runtime::design::read_report(&report_path)
                .map_err(|e| format!("{report_path}: {e}"))?;
            let scope = value(rest, "--scope")?.ok_or("design candidates requires --scope")?;
            let target_kind =
                value(rest, "--target-kind")?.ok_or("design candidates requires --target-kind")?;
            let variant = value(rest, "--variant")?.unwrap_or_else(|| "default".into());
            let rationale = value(rest, "--rationale")?.unwrap_or_default();
            let mut proposals = Vec::new();
            for (i, arg) in rest.iter().enumerate() {
                if arg == "--candidate" {
                    let spec = rest
                        .get(i + 1)
                        .ok_or("--candidate requires DIMENSION:RECORD_ID[,..]")?;
                    let roots = spec
                        .split(',')
                        .map(runtime::design::parse_root)
                        .collect::<Result<Vec<_>, _>>()?;
                    proposals.push(runtime::design::Proposal {
                        roots,
                        bindings: Vec::new(),
                        scope: scope.clone(),
                        target_kind: target_kind.clone(),
                        variant: variant.clone(),
                        rationale: rationale.clone(),
                        evidence_ref: report_path.clone(),
                    });
                }
            }
            let designs = runtime::design::propose_candidates(&atlas, &report, proposals)
                .map_err(|e| format!("{atlas}: {e}"))?;
            let mut written = Vec::new();
            let mut rejected = Vec::new();
            for (design, violations) in &designs {
                let hex = design
                    .design_id
                    .rsplit(':')
                    .next()
                    .unwrap_or(&design.design_id);
                let path = format!("{out_dir}/{hex}.json");
                write_report_to_out(&path, &(json(design)? + "\n"))?;
                written.push(path);
                rejected.extend(violations.iter().cloned());
            }
            println!("{}", json(&written)?);
            if !rejected.is_empty() {
                return Err(format!("DESIGN_REJECTED: {}", json(&rejected)?));
            }
        }
        [cmd, sub, rest @ ..] if cmd == "design" && sub == "compare" => {
            // G150 (ADR 0066): compare `--design` files over the verified container by the
            // criteria in `--criteria`; the Pareto front is kept as a set. Exits
            // COMPARISON_REFUSED when the comparison cannot be made. Never selects.
            let atlas = value(rest, "--atlas")?.ok_or("design compare requires --atlas")?;
            let criteria_path =
                value(rest, "--criteria")?.ok_or("design compare requires --criteria")?;
            let criteria = runtime::design::read_criteria(&criteria_path)
                .map_err(|e| format!("{criteria_path}: {e}"))?;
            let report = match value(rest, "--report")? {
                Some(path) => {
                    Some(runtime::design::read_report(&path).map_err(|e| format!("{path}: {e}"))?)
                }
                None => None,
            };
            let mut designs = Vec::new();
            for (i, arg) in rest.iter().enumerate() {
                if arg == "--design" {
                    let path = rest.get(i + 1).ok_or("--design requires a path")?;
                    designs.push(
                        runtime::design::read_design(path).map_err(|e| format!("{path}: {e}"))?,
                    );
                }
            }
            let outcome = runtime::design::compare(&atlas, report.as_ref(), &designs, &criteria)
                .map_err(|e| format!("{atlas}: {e}"))?;
            match outcome {
                Ok(comparison) => {
                    let text = json(&comparison)? + "\n";
                    match value(rest, "--out")? {
                        Some(out) => write_report_to_out(&out, &text)?,
                        None => print!("{text}"),
                    }
                }
                Err(violations) => {
                    return Err(format!("COMPARISON_REFUSED: {}", json(&violations)?));
                }
            }
        }
        [cmd, sub, rest @ ..] if cmd == "design" && sub == "check" => {
            // G148 (ADR 0064): check a design in its state against the verified container, the
            // verification report and the repository's declared principals. Exits
            // DESIGN_REJECTED unless it is accepted.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let design_path = value(rest, "--design")?.ok_or("design check requires --design")?;
            let atlas = value(rest, "--atlas")?.ok_or("design check requires --atlas")?;
            let design = runtime::design::read_design(&design_path)
                .map_err(|e| format!("{design_path}: {e}"))?;
            let report = match value(rest, "--report")? {
                Some(path) => {
                    Some(runtime::design::read_report(&path).map_err(|e| format!("{path}: {e}"))?)
                }
                None => None,
            };
            let registry =
                runtime::design::read_registry(&root).map_err(|e| format!("{root}: {e}"))?;
            let comparison = match value(rest, "--comparison")? {
                Some(path) => Some(
                    runtime::design::read_comparison(&path).map_err(|e| format!("{path}: {e}"))?,
                ),
                None => None,
            };
            let checked = runtime::design::check(
                &design,
                &atlas,
                report.as_ref(),
                &registry,
                comparison.as_ref(),
            )
            .map_err(|e| format!("{atlas}: {e}"))?;
            let text = json(&checked)? + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
            if checked.verdict != runtime::design::Verdict::Accepted {
                return Err(format!("DESIGN_REJECTED: {}", json(&checked.violations)?));
            }
        }
        [cmd, sub, rest @ ..] if cmd == "integrity" && sub == "envelope" => {
            // G138 (ADR 0056): the architectural integrity envelope the ADL declares. `--check`
            // exits INTEGRITY_ENVELOPE_DRIFT when the pinned envelope differs from it.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let envelope =
                runtime::integrity::envelope(&root).map_err(|e| format!("{root}: {e}"))?;
            let text = json(&envelope)? + "\n";
            if rest.iter().any(|arg| arg == "--check") {
                let path =
                    std::path::Path::new(&root).join(runtime::integrity::PINNED_ENVELOPE_PATH);
                let pinned = fs::read_to_string(&path).unwrap_or_default();
                if pinned != text {
                    return Err(format!(
                        "INTEGRITY_ENVELOPE_DRIFT: {} differs from the declared envelope; re-pin \
                         with `atlas-systemizer integrity envelope --out {}`",
                        path.display(),
                        runtime::integrity::PINNED_ENVELOPE_PATH
                    ));
                }
            }
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
        }
        [cmd, sub, rest @ ..] if cmd == "integrity" && sub == "report" => {
            // G138 (ADR 0056): evaluate the pinned envelope against the repository's census;
            // exits INTEGRITY_NOT_ELIGIBLE unless the verdict is ELIGIBLE.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let pinned_path = value(rest, "--envelope")?.unwrap_or_else(|| {
                std::path::Path::new(&root)
                    .join(runtime::integrity::PINNED_ENVELOPE_PATH)
                    .display()
                    .to_string()
            });
            let pinned = runtime::integrity::read_envelope(&pinned_path)
                .map_err(|e| format!("{pinned_path}: {e}"))?;
            let report =
                runtime::integrity::report(&root, &pinned).map_err(|e| format!("{root}: {e}"))?;
            let problems = runtime::integrity::check_report(&report, &pinned);
            if !problems.is_empty() {
                return Err(format!(
                    "INTEGRITY_REPORT_INCONSISTENT: {}",
                    problems.join("; ")
                ));
            }
            let text = json(&report)? + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
            if report.verdict != runtime::integrity::IntegrityVerdict::Eligible {
                return Err(format!("INTEGRITY_NOT_ELIGIBLE: {}", report.verdict));
            }
        }
        [cmd, sub, rest @ ..] if cmd == "recensus" && sub == "snapshot" => {
            // ADR 0024: the revision-independent semantic state of a full self-census.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let out = value(rest, "--out")?.ok_or("recensus snapshot requires --out")?;
            let snapshot =
                runtime::recensus::snapshot(&root).map_err(|e| format!("{root}: {e}"))?;
            write_report_to_out(&out, &(json(&snapshot)? + "\n"))?;
            println!("{} {}", snapshot.census_digest, snapshot.revision);
        }
        [cmd, sub, rest @ ..] if cmd == "recensus" && sub == "prove" => {
            // ADR 0024: census the candidate twice, diff it against the pre-change census, and
            // decide the generation. Exits GENERATION_NOT_PROVEN unless every observed change is
            // intended (or accepted with a reason), every intention is observed, the replay is
            // identical and no forbidden regression remains.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let generation =
                value(rest, "--generation")?.ok_or("recensus prove requires --generation")?;
            let before_path = value(rest, "--before")?.ok_or("recensus prove requires --before")?;
            let intent_path = value(rest, "--intent")?.ok_or("recensus prove requires --intent")?;
            let before =
                runtime::recensus::read_snapshot(&before_path).map_err(|e| e.to_string())?;
            let intent_text =
                fs::read_to_string(&intent_path).map_err(|e| format!("{intent_path}: {e}"))?;
            let intent: runtime::recensus::RecensusIntent =
                serde_json::from_str(&intent_text).map_err(|e| format!("{intent_path}: {e}"))?;
            let (report, after) =
                runtime::recensus::prove_candidate(&root, &generation, &before, &intent)
                    .map_err(|e| format!("{root}: {e}"))?;
            if let Some(after_out) = value(rest, "--after-out")? {
                write_report_to_out(&after_out, &(json(&after)? + "\n"))?;
            }
            let text = json(&report)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            if report.verdict != runtime::recensus::Verdict::Proven {
                return Err("GENERATION_NOT_PROVEN".into());
            }
        }
        [cmd, sub, rest @ ..] if cmd == "donors" && sub == "working-set" => {
            // ADR 0021: measure disk + local donor source, check storage integrity, and (with
            // --request) decide whether a donor may be materialized now.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let request = match value(rest, "--request")? {
                None => None,
                Some(donor) => {
                    let mode = value(rest, "--mode")?.unwrap_or_else(|| "SPARSE_CHECKOUT".into());
                    let mode: runtime::donor_storage::MaterializationMode =
                        serde_json::from_str(&format!("\"{mode}\""))
                            .map_err(|_| format!("--mode: unknown materialization mode {mode}"))?;
                    let bytes = |flag: &str| -> Result<u64, String> {
                        value(rest, flag)?.map_or(Ok(0), |v| {
                            v.parse()
                                .map_err(|_| format!("{flag} expects a byte count"))
                        })
                    };
                    Some(runtime::donor_storage::AdmissionRequest {
                        donor,
                        mode,
                        estimated_source_bytes: bytes("--source-bytes")?,
                        estimated_build_bytes: bytes("--build-bytes")?,
                    })
                }
            };
            let measure = !rest.iter().any(|arg| arg == "--no-sizes");
            let report = runtime::donor_storage::working_set_report(
                std::path::Path::new(&root),
                request.as_ref(),
                measure,
            )
            .map_err(|e| format!("{root}: {e}"))?;
            let text = json(&report)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            if !report.unrecorded_violations.is_empty() {
                return Err("DONOR_STORAGE_INTEGRITY_VIOLATION".into());
            }
            if report.admission.as_ref().is_some_and(|a| !a.admitted()) {
                return Err("DONOR_MATERIALIZATION_REFUSED".into());
            }
        }
        [cmd, rest @ ..] if cmd == "search" => {
            // ADR 0020: generate originality-valid candidates over a genome, create and verify
            // each, and keep the Pareto front of the verified ones (a set, not a winner).
            let genome_path = value(rest, "--genome")?.ok_or("search requires --genome")?;
            let out_dir = value(rest, "--out-dir")?.ok_or("search requires --out-dir")?;
            let count = match value(rest, "--count")? {
                Some(n) => n
                    .parse::<usize>()
                    .ok()
                    .filter(|n| *n > 0)
                    .ok_or_else(|| format!("--count expects a positive integer, got {n}"))?,
                None => 3,
            };
            let text =
                fs::read_to_string(&genome_path).map_err(|e| format!("{genome_path}: {e}"))?;
            let genome: runtime::visual::DesignGenome =
                serde_json::from_str(&text).map_err(|e| format!("{genome_path}: {e}"))?;
            let report =
                runtime::visual::search_designs(&genome, count, std::path::Path::new(&out_dir))
                    .map_err(|e| format!("{out_dir}: {e}"))?;
            let text = json(&report)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            if report.pareto_front.is_empty() {
                return Err("NO_VERIFIED_CANDIDATE".into());
            }
        }
        [cmd, rest @ ..] if cmd == "create" => {
            // Creator construction loop (ADR 0017): intent -> HTML/CSS -> render -> re-observe ->
            // verify every intended relation.
            let out = value(rest, "--out")?.ok_or("create requires --out (the page to write)")?;
            if let Some(genome_path) = value(rest, "--genome")? {
                // ADR 0018: RECOMBINE -> CREATE -> VERIFY from a genome and a recipe.
                let recipe_path = value(rest, "--recipe")?.ok_or("--genome requires --recipe")?;
                let read =
                    |path: &str| fs::read_to_string(path).map_err(|e| format!("{path}: {e}"));
                let genome: runtime::visual::DesignGenome =
                    serde_json::from_str(&read(&genome_path)?)
                        .map_err(|e| format!("{genome_path}: {e}"))?;
                let recipe: runtime::visual::Recombination =
                    serde_json::from_str(&read(&recipe_path)?)
                        .map_err(|e| format!("{recipe_path}: {e}"))?;
                let report = runtime::visual::recombine_and_create(
                    &genome,
                    &recipe,
                    std::path::Path::new(&out),
                )
                .map_err(|e| format!("{out}: {e}"))?;
                let text = json(&report)? + "\n";
                if let Some(report_out) = value(rest, "--report")? {
                    write_report_to_out(&report_out, &text)?;
                }
                print!("{text}");
                if !report.creation.verdict.admits() {
                    return Err("CREATION_NOT_VERIFIED".into());
                }
                return Ok(());
            }
            let intent_path =
                value(rest, "--intent")?.ok_or("create requires --intent or --genome")?;
            let text =
                fs::read_to_string(&intent_path).map_err(|e| format!("{intent_path}: {e}"))?;
            let intent: runtime::visual::CreatorIntent =
                serde_json::from_str(&text).map_err(|e| format!("{intent_path}: {e}"))?;
            let report = runtime::visual::create_and_verify(&intent, std::path::Path::new(&out))
                .map_err(|e| format!("{out}: {e}"))?;
            let text = json(&report)? + "\n";
            if let Some(report_out) = value(rest, "--report")? {
                write_report_to_out(&report_out, &text)?;
            }
            print!("{text}");
            if !report.verdict.admits() {
                return Err("CREATION_NOT_VERIFIED".into());
            }
        }
        [cmd, rest @ ..] if cmd == "observe" => {
            // Creator Fabric (ADR 0011): observe an authorized local fixture through the
            // sandboxed browser instrument; one `--viewport WxH` per viewport (default 1280x800
            // and 375x800).
            let fixture = value(rest, "--fixture")?.ok_or("observe requires --fixture")?;
            let mut viewports = Vec::new();
            for (i, arg) in rest.iter().enumerate() {
                if arg == "--viewport" {
                    let spec = rest.get(i + 1).ok_or("--viewport requires a value")?;
                    let parsed = spec
                        .split_once('x')
                        .and_then(|(w, h)| Some((w.parse().ok()?, h.parse().ok()?)))
                        .ok_or_else(|| format!("--viewport expects WIDTHxHEIGHT, got {spec}"))?;
                    viewports.push(parsed);
                }
            }
            if viewports.is_empty() {
                viewports = vec![(1280, 800), (375, 800)];
            }
            // `--bisect`: locate every responsive change between the narrowest and widest
            // viewport to a single pixel by re-observation (INFERRED breakpoints).
            let fixture_path = std::path::Path::new(&fixture);
            if let Some(pair) = value(rest, "--differential")? {
                // ADR 0022: the same subject through two instruments, compared through the same
                // Atlas semantics (layout + bisected breakpoints).
                let (a, b) = pair
                    .split_once(',')
                    .ok_or("--differential expects INSTRUMENT_A,INSTRUMENT_B")?;
                let resolve = |id: &str| {
                    runtime::visual::instrument(id)
                        .ok_or_else(|| format!("unknown instrument {id}"))
                };
                let (left, right) = (resolve(a)?, resolve(b)?);
                let narrow = viewports.iter().map(|v| v.0).min().unwrap_or(375);
                let wide = viewports.iter().map(|v| v.0).max().unwrap_or(1280);
                let report = runtime::visual::cross_instrument_layout(
                    left.as_ref(),
                    right.as_ref(),
                    fixture_path,
                    narrow,
                    wide,
                    viewports[0].1,
                )
                .map_err(|e| format!("{fixture}: {e}"))?;
                let mut report = report;
                // Recorded investigations (CREATOR-INSTRUMENTS.toml), keyed by the fixture path
                // as given; anything they do not cover stays UNCLASSIFIED.
                runtime::visual::apply_recorded_classifications(
                    &mut report.layout,
                    std::path::Path::new("."),
                    &fixture,
                )
                .map_err(|e| format!("{}: {e}", runtime::visual::INSTRUMENT_REGISTRY))?;
                let text = json(&report)? + "\n";
                if let Some(out) = value(rest, "--out")? {
                    write_report_to_out(&out, &text)?;
                }
                print!("{text}");
                return Ok(());
            }
            if let Some(id) = value(rest, "--instrument")? {
                let instrument = runtime::visual::instrument(&id)
                    .ok_or_else(|| format!("unknown instrument {id}"))?;
                let report = runtime::visual::observe_fixture_with(
                    instrument.as_ref(),
                    fixture_path,
                    &viewports,
                )
                .map_err(|e| format!("{fixture}: {e}"))?;
                let text = json(&report)? + "\n";
                if let Some(out) = value(rest, "--out")? {
                    write_report_to_out(&out, &text)?;
                }
                print!("{text}");
                return Ok(());
            }
            if rest.iter().any(|arg| arg == "--motion") {
                // ADR 0016: deterministic curve sampling + easing inference.
                let report = runtime::visual::motion_fixture(fixture_path, viewports[0])
                    .map_err(|e| format!("{fixture}: {e}"))?;
                let text = json(&report)? + "\n";
                if let Some(out) = value(rest, "--out")? {
                    write_report_to_out(&out, &text)?;
                }
                print!("{text}");
                return Ok(());
            }
            if rest.iter().any(|arg| arg == "--interact") {
                // ADR 0015: hover/click/click-twice/focus stimuli at the first viewport.
                let report = runtime::visual::interact_fixture(fixture_path, viewports[0])
                    .map_err(|e| format!("{fixture}: {e}"))?;
                let text = json(&report)? + "\n";
                if let Some(out) = value(rest, "--out")? {
                    write_report_to_out(&out, &text)?;
                }
                print!("{text}");
                return Ok(());
            }
            let report = if rest.iter().any(|arg| arg == "--bisect") {
                let narrow = viewports.iter().map(|v| v.0).min().unwrap_or(375);
                let wide = viewports.iter().map(|v| v.0).max().unwrap_or(1280);
                runtime::visual::bisect_breakpoints(fixture_path, narrow, wide, viewports[0].1)
            } else {
                runtime::visual::observe_fixture(fixture_path, &viewports)
            }
            .map_err(|e| format!("{fixture}: {e}"))?;
            let text = json(&report)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
        }
        [cmd, sub, rest @ ..] if cmd == "work" && sub == "prepare" => {
            let root = value(rest, "--root")?.ok_or("work prepare requires --root")?;
            let goal = value(rest, "--goal")?.ok_or("work prepare requires --goal")?;
            let expected_base_sha = value(rest, "--base-sha")?;
            let report = runtime::prepare_work(&root, goal, expected_base_sha)
                .map_err(|e| format!("{root}: {e}"))?;
            let text = json(&report)? + "\n";
            if let Some(out) = value(rest, "--out")? {
                write_report_to_out(&out, &text)?;
            }
            print!("{text}");
            if !report.allowed {
                return Err("WORK_PREPARE_NOT_ALLOWED".into());
            }
        }
        [cmd, sub, rest @ ..] if cmd == "verification" && sub == "self" => {
            // G127 (ADR 0048): the self scope's SEMANTIC/UNIT/COMPATIBILITY obligations evaluated
            // against evidence bound to the candidate's census digest.
            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
            let recensus =
                value(rest, "--recensus")?.ok_or("verification self requires --recensus")?;
            let (report, evidence) = runtime::verification::verify_self(
                std::path::Path::new(&root),
                std::path::Path::new(&recensus),
            )
            .map_err(|e| format!("{root}: {e}"))?;
            let text = json(&serde_json::json!({"report": report, "evidence": evidence}))? + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
            if report.verdict != "ADMISSIBLE" {
                return Err(format!(
                    "VERIFICATION_BLOCKED: {}",
                    report.blockers.join("; ")
                ));
            }
        }
        [cmd, sub, ..] if cmd == "sandbox" && sub == "probe" => {
            // G126 (ADR 0047): the isolation the restricted-subprocess backend can enforce here.
            let network = runtime::sandbox::network_isolation_available();
            let probe = serde_json::json!({
                "backend": runtime::sandbox::RESTRICTED_SUBPROCESS,
                "enforced": ["ENVIRONMENT_CLEARED", "INPUTS_STAGED", "WORKING_DIRECTORY_CONFINED", "STDIN_CLOSED", "TIME_LIMITED"],
                "network_denied": if network { "ENFORCED" } else { "UNENFORCED: unprivileged user namespaces are unavailable on this host" },
                "filesystem_confined": "UNENFORCED: no filesystem namespace or Landlock ruleset in this class",
            });
            println!("{}", json(&probe)?);
        }
        [cmd, op, rest @ ..] if cmd == "agent" => {
            // G122 (ADR 0044): the Agent-Worn Atlas operations over the composed world model.
            // `--model <world-model.json>` reuses a composed model; otherwise `--root` is censused
            // and composed first.
            use runtime::agent::lens;
            let model = match value(rest, "--model")? {
                Some(path) => {
                    runtime::agent::read_world_model(&path).map_err(|e| format!("{path}: {e}"))?
                }
                None => {
                    let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
                    runtime::agent::world_model(&root).map_err(|e| format!("{root}: {e}"))?
                }
            };
            let target = || value(rest, "--target")?.ok_or(format!("agent {op} requires --target"));
            let text = match op.as_str() {
                "model" => json(&model)?,
                "understand" => {
                    let mission = value(rest, "--mission")?.unwrap_or_default();
                    let context = lens::understand(&model, &target()?, &mission)?;
                    let digest = runtime::agent::structural_digest(&context);
                    let mut value = serde_json::to_value(&context).map_err(|e| e.to_string())?;
                    value["structural_digest"] = serde_json::Value::String(digest);
                    json(&value)?
                }
                "explain" => json(&lens::explain(&model, &target()?)?)?,
                "impact" => {
                    let targets = target()?;
                    let list: Vec<&str> = targets.split(',').collect();
                    json(&lens::impact(&model, &list)?)?
                }
                "trace" | "why" | "compare" => {
                    let from =
                        value(rest, "--from")?.ok_or(format!("agent {op} requires --from"))?;
                    let to = value(rest, "--to")?.ok_or(format!("agent {op} requires --to"))?;
                    match op.as_str() {
                        "trace" => json(&lens::trace(&model, &from, &to)?)?,
                        "why" => json(&lens::why(&model, &from, &to)?)?,
                        _ => json(&lens::compare(&model, &from, &to)?)?,
                    }
                }
                "invariants" => json(&lens::invariants(&model, &target()?)?)?,
                "unknowns" => {
                    let index = lens::Index::new(&model);
                    json(&lens::unknowns(&index, &index.resolve(&target()?)?))?
                }
                "effects" => {
                    let index = lens::Index::new(&model);
                    json(&lens::effects(&index, &index.resolve(&target()?)?))?
                }
                "state" => json(&lens::state_model(&model, &target()?)?)?,
                "dependencies" => json(&lens::dependencies(&model, &target()?)?)?,
                "capabilities" => json(&lens::capabilities(&model, &target()?)?)?,
                "resources" => json(&lens::unanswerable(&model, "GAP-RESOURCE"))?,
                "causal" => json(&lens::unanswerable(&model, "GAP-CAUSALITY"))?,
                "plan" => json(&lens::plan(&model, &target()?)?)?,
                "hypothesis" => {
                    let claim =
                        value(rest, "--claim")?.ok_or("agent hypothesis requires --claim")?;
                    json(&lens::hypothesis(&model, &claim)?)?
                }
                "benchmark" => {
                    let cases = value(rest, "--cases")?
                        .unwrap_or_else(|| ".atlas/evidence/agent/benchmark.json".into());
                    let cases = runtime::agent::read_benchmark(&cases)
                        .map_err(|e| format!("{cases}: {e}"))?;
                    json(&runtime::agent::run_benchmark(&model, &cases))?
                }
                "closure" => {
                    // G129 (NA-IMPACT-CLOSURE): the affected-impact closure of a change, checked
                    // against the full-recompute diff of the two models.
                    let before =
                        value(rest, "--before")?.ok_or("agent closure requires --before")?;
                    let before = runtime::agent::read_world_model(&before)
                        .map_err(|e| format!("{before}: {e}"))?;
                    let changed: Vec<String> = match value(rest, "--changed")? {
                        Some(list) => list.split(',').map(str::to_owned).collect(),
                        None => {
                            let range = value(rest, "--git")?
                                .ok_or("agent closure requires --changed or --git <from>..<to>")?;
                            let (from, to) =
                                range.split_once("..").ok_or("--git takes <from>..<to>")?;
                            let root = value(rest, "--root")?.unwrap_or_else(|| ".".into());
                            runtime::agent::changed_paths(&root, from, to)
                                .map_err(|e| format!("{range}: {e}"))?
                        }
                    };
                    let (result, oracle) =
                        runtime::agent::impact_closure(&before, &model, &changed);
                    json(&serde_json::json!({ "closure": result, "oracle": oracle }))?
                }
                "verify" => {
                    let before =
                        value(rest, "--before")?.ok_or("agent verify requires --before")?;
                    let before = runtime::agent::read_world_model(&before)
                        .map_err(|e| format!("{before}: {e}"))?;
                    let delta = lens::verify(&before, &model);
                    let regressed = delta.verdict != "HELD";
                    let text = json(&delta)? + "\n";
                    print!("{text}");
                    if regressed {
                        return Err("INVARIANTS_REGRESSED".into());
                    }
                    return Ok(());
                }
                other => {
                    return Err(format!(
                        "unknown agent operation `{other}`: model|understand|explain|impact|trace|why|compare|invariants|unknowns|effects|state|dependencies|capabilities|resources|causal|plan|hypothesis|benchmark|verify"
                    ));
                }
            } + "\n";
            match value(rest, "--out")? {
                Some(out) => write_report_to_out(&out, &text)?,
                None => print!("{text}"),
            }
        }
        _ => {
            return Err(
                "usage: atlas-systemizer <contract|systemize|docs audit|code analyze|parse|check|graph|observe|genome|search|create|physical|product|census certificate|adl derive|integrity envelope|integrity report|atlas pack|atlas verify|atlas seal|seal gate|weights census|weights construct|recensus snapshot|recensus prove|donors working-set|work prepare|agent|sandbox probe|verification self> ..."
                    .into(),
            );
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("atlas-systemizer: {message}");
            ExitCode::from(2)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Falsification: `io::Error::to_string()` never includes the path that failed -- it is purely
    // the OS message ("No such file or directory (os error 2)"). Every subcommand handler passed
    // that bare string straight through via `.map_err(|e| e.to_string())`, so a mistyped or
    // nonexistent `--root` (arguably the single most common CLI usage mistake) produced a message
    // with no indication of which path was the problem, indistinguishable from any other io
    // failure anywhere in the pipeline. Confirmed against the unfixed code before writing the fix.
    #[test]
    fn a_nonexistent_root_error_names_the_offending_path() {
        let root = "/tmp/atlas-cli-tests-definitely-does-not-exist-xyz789";
        let out = std::env::temp_dir()
            .join("atlas-cli-tests-out.json")
            .to_string_lossy()
            .into_owned();
        let err = run(&[
            "systemize".to_owned(),
            "--root".to_owned(),
            root.to_owned(),
            "--out".to_owned(),
            out,
        ])
        .expect_err("a nonexistent root must not succeed");
        assert!(
            err.contains(root),
            "error message must name the offending root path, got: {err}"
        );
    }

    // Falsification: the same defect class as the `--root` fix above, in the output path instead
    // of the input one. `write_report_to_out`'s two `fs::create_dir_all`/`fs::write` calls used
    // `.map_err(|e| e.to_string())` (no path context) until this fix -- confirmed against the
    // unfixed code with a real repository root (this repo itself, via `check`, the cheapest
    // subcommand to run) and an `--out` path whose parent component is a real, existing FILE
    // (`fs::create_dir_all` cannot create a directory through a file: `ENOTDIR`), producing "Not a
    // directory (os error 20)" with no indication of which path was the problem.
    #[test]
    fn an_unwritable_out_path_error_names_the_offending_path() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let blocking_file = std::env::temp_dir().join(format!("atlas-cli-tests-blocker-{nonce}"));
        std::fs::write(&blocking_file, b"not a directory").unwrap();
        let out = blocking_file
            .join("nested")
            .join("out.json")
            .to_string_lossy()
            .into_owned();

        let err = run(&[
            "check".to_owned(),
            "--root".to_owned(),
            ".".to_owned(),
            "--out".to_owned(),
            out.clone(),
        ])
        .expect_err("an --out path blocked by an existing file must not succeed");
        assert!(
            err.contains(&out),
            "error message must name the offending --out path, got: {err}"
        );

        std::fs::remove_file(&blocking_file).unwrap();
    }

    // Falsification: `docs audit`, `check`, and `work prepare` each enforce their own report's
    // readiness field with a distinct error (`DOCS_GATE_NOT_READY`/`ADL_CHECK_NOT_READY`/
    // `WORK_PREPARE_NOT_ALLOWED`) so a blocked repository makes the process exit non-zero.
    // `systemize` -- the one subcommand `.atlas/repo.toml`'s own `compile` command invokes --
    // silently dropped this check: no branch in its handler could ever return `Err`, so a
    // repository with `coding_admission.allowed == false` (e.g. no admitted `.atlas/repo.toml` at
    // all, `REPO_GATE_NOT_READY`) still exited 0. Confirmed against the unfixed code before
    // writing this fix.
    #[test]
    fn a_repository_with_no_admitted_manifest_makes_systemize_exit_non_zero() {
        let dir = std::env::temp_dir().join(format!(
            "atlas-cli-tests-no-manifest-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // `runtime::systemize` requires a real git repository (it pins identity via
        // `git rev-parse HEAD`) -- this scratch repo has a commit but deliberately no
        // `.atlas/repo.toml` at all, the exact `REPO_GATE_NOT_READY` shape.
        let run_git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(&dir)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        run_git(&["init", "--quiet"]);
        run_git(&["config", "user.email", "test@example.com"]);
        run_git(&["config", "user.name", "test"]);
        std::fs::write(dir.join("README.md"), "no atlas manifest here\n").unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "--quiet", "-m", "init"]);
        let out_path = dir.join("out.json");
        let out = out_path.to_string_lossy().into_owned();

        let err = run(&[
            "systemize".to_owned(),
            "--root".to_owned(),
            dir.to_string_lossy().into_owned(),
            "--out".to_owned(),
            out,
        ])
        .expect_err("a repository with no admitted manifest must not exit successfully");
        assert_eq!(err, "CODING_ADMISSION_NOT_ALLOWED");

        // `runtime::systemize` computes 8 independent blocker conditions
        // (REPO_GATE_NOT_READY, DOCS_GATE_NOT_READY, ADL_DIAGNOSTICS_PRESENT,
        // ADL_CONSTRAINT_VIOLATED, INVENTORY/CENSUS/NORMALIZATION/SEMANTIC_EXTRACTION_
        // ACCOUNTING_NOT_CLOSED, DEPENDENCY_CLOSURE_NOT_CLOSED) and has zero direct unit test
        // coverage anywhere in the runtime crate -- this was the only test exercising it at all,
        // and its assertion above proves only that SOME blocker fired, which is trivially true
        // here regardless of whether the other 7 conditions are computed correctly (this bare
        // repository's missing `.atlas/repo.toml` alone guarantees `blockers` is non-empty). A
        // bug swapping two blocker labels, or wrongly raising/suppressing an unrelated condition,
        // would leave this test passing unchanged. Reading the report back and asserting the
        // EXACT blocker list this real, minimal fixture produces closes that gap.
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&out_path).unwrap()).unwrap();
        assert_eq!(
            report["coding_admission"]["blockers"],
            serde_json::json!(["REPO_GATE_NOT_READY", "DOCS_GATE_NOT_READY"]),
            "exactly these two conditions -- no fewer, no more, no others -- must fire for a bare \
             git repository with no .atlas/ directory at all: {report:#}"
        );

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn systemize_previous_reports_exactly_the_changed_artifacts_and_refuses_a_foreign_baseline() {
        let nonce = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!("atlas-cli-tests-delta-{nonce}"));
        let dir = base.join("repo");
        std::fs::create_dir_all(&dir).unwrap();
        let run_git = |args: &[&str]| {
            let status = std::process::Command::new("git")
                .args(args)
                .current_dir(&dir)
                .status()
                .unwrap();
            assert!(status.success(), "git {args:?} failed");
        };
        run_git(&["init", "--quiet"]);
        run_git(&["config", "user.email", "test@example.com"]);
        run_git(&["config", "user.name", "test"]);
        std::fs::write(dir.join("README.md"), "first\n").unwrap();
        std::fs::write(dir.join("stable.txt"), "unchanged\n").unwrap();
        std::fs::write(dir.join("doomed.txt"), "to be deleted\n").unwrap();
        run_git(&["add", "."]);
        run_git(&["commit", "--quiet", "-m", "init"]);
        let root = dir.to_string_lossy().into_owned();
        // Reports live outside the scanned root so they never appear in its inventory.
        let first = base.join("first.json").to_string_lossy().into_owned();
        let second = base.join("second.json").to_string_lossy().into_owned();
        let systemize = |extra: &[&str], out: &str| {
            let mut args = vec!["systemize", "--root", &root, "--out", out];
            args.extend_from_slice(extra);
            run(&args.iter().map(|a| (*a).to_owned()).collect::<Vec<_>>())
        };
        // Not admitted (no .atlas/repo.toml), but the report is still written.
        let _ = systemize(&[], &first);
        let baseline: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&first).unwrap()).unwrap();
        assert!(
            baseline.get("inventory_delta").is_none(),
            "a first run has no baseline"
        );

        std::fs::write(dir.join("README.md"), "second\n").unwrap();
        std::fs::write(dir.join("stable.txt"), "unchanged\n").unwrap(); // rewritten, same bytes
        std::fs::remove_file(dir.join("doomed.txt")).unwrap();
        std::fs::write(dir.join("new.txt"), "hello\n").unwrap();
        let _ = systemize(&["--previous", &first], &second);
        let report: serde_json::Value =
            serde_json::from_str(&std::fs::read_to_string(&second).unwrap()).unwrap();
        let delta = &report["inventory_delta"];
        let changes: Vec<(String, String, String)> = delta["changes"]
            .as_array()
            .unwrap()
            .iter()
            .map(|c| {
                (
                    c["path"].as_str().unwrap().to_owned(),
                    c["change"].as_str().unwrap().to_owned(),
                    c["cause"].as_str().unwrap().to_owned(),
                )
            })
            .collect();
        let expected = [
            ("README.md", "MODIFIED", "CONTENT_DIGEST_DIFFERS"),
            ("doomed.txt", "DELETED", "DISAPPEARED"),
            ("new.txt", "CREATED", "APPEARED"),
        ]
        .map(|(p, k, c)| (p.to_owned(), k.to_owned(), c.to_owned()));
        assert_eq!(changes, expected, "{delta:#}");

        let mut foreign = baseline.clone();
        foreign["inventory"]["root"] = serde_json::json!("/somewhere/else");
        let foreign_path = base.join("foreign.json").to_string_lossy().into_owned();
        std::fs::write(&foreign_path, foreign.to_string()).unwrap();
        let err = systemize(&["--previous", &foreign_path], &second)
            .expect_err("a baseline from another root must be refused");
        assert!(err.contains("inventory roots differ"), "{err}");

        std::fs::remove_dir_all(&base).unwrap();
    }

    // Falsification: `--base-sha` is genuinely optional (`Option<String>`), so before this fix
    // `value()` returning `None` for "flag present but its value is missing" was silently
    // indistinguishable from "flag never passed at all" -- exactly the shape a common
    // shell-scripting mistake produces (`--base-sha "$BASE_SHA"` with `$BASE_SHA` unset/empty,
    // dropped entirely by word-splitting). That would have silently skipped
    // `EXACT_BASE_SHA_REQUIRED`'s drift check instead of failing loud on malformed invocation.
    // Confirmed against the unfixed code before writing this fix.
    #[test]
    fn a_base_sha_flag_with_no_following_value_is_a_usage_error_not_a_silent_none() {
        let err = run(&[
            "work".to_owned(),
            "prepare".to_owned(),
            "--root".to_owned(),
            ".".to_owned(),
            "--goal".to_owned(),
            "fix bug".to_owned(),
            "--base-sha".to_owned(),
        ])
        .expect_err("a --base-sha flag with no following value must never succeed silently");
        assert_eq!(err, "--base-sha requires a value");
    }

    // Same defect class, the required-flag side: `--root` present but with no following value
    // must be reported as a malformed flag, not conflated with "--root was never passed".
    #[test]
    fn a_root_flag_with_no_following_value_is_a_usage_error() {
        let err = run(&["check".to_owned(), "--root".to_owned()])
            .expect_err("a --root flag with no following value must never succeed silently");
        assert_eq!(err, "--root requires a value");
    }
}
