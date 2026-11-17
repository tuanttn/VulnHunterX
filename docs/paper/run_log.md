# Run log – VulnHunterX experiment v3.3

Hand-written summary (plan.md §10.4). Raw per-call logs stay outside git; this file records paths and hashes.
`docs/paper/` is git-ignored: use `git add -f docs/paper/run_log.md` only on purpose.

## Day 1 – Wed 18 Nov 2026 – P0 Environment (set up 17 Nov, machine clock)

Status: environment and datasets ready. Not done: model pin, API key, storage decision (all need Tuannt).

### Toolchain (B0)
| Item | Value |
| --- | --- |
| Python | 3.12.10, venv `VulnHunterX_Paper/.venv` (git-ignored); `pip install -e ".[dev,benchmark]"` |
| Key packages | litellm 1.109.1, tree-sitter 0.26.1, pytest 9.2.0, ruff 0.17.5, mypy 2.4.1 |
| CodeQL CLI | 2.27.4 (bundle at `tools/codeql`, reused, not re-downloaded) |
| CodeQL query pack | `codeql/java-queries` 1.12.0; `codeql/java-all` 9.3.4; suite `codeql-suites/java-security-extended.qls` resolves to 124 queries |
| JDK | Temurin 21.0.13+9, `tools/jdk/jdk-21.0.13+9`, SHA-256 `a4dbaa05fca4bd89d84584e58c459bd732efebb1722af80ab13c6516832004f9` (checked against the Adoptium API value) |
| Activation | `. D:\Project\VulnHunterX\exp-data\scripts\env.ps1` |
| `vuln-hunter-x check-env` | CodeQL OK, tree-sitter OK. Semgrep/OpenGrep not installed (not needed: CodeQL only). No LLM key set |

CodeQL toolchain smoke (synthetic Java, no dataset): `database create --build-mode=none` rc 0 (46 s), `database analyze` with the suite rc 0 (~56 s), SARIF produced.
Seen: `java/relative-path-command` and `java/concatenated-command-line` alerts; SARIF CWE tags are `external/cwe/cwe-078` (3-digit, lower-case) → normalisation to `CWE-78` is required. **Not yet seen:** a taint-flow alert (`SqlTainted`/`ExecTainted`) with `codeFlows`; check on the OWASP scan (day 2).
`codeql resolve qlpacks` prints "found in N same-priority locations" warnings for the bundled packs (same versions, duplicated under `.codeql/libraries`). `resolve queries` and `database analyze` work regardless.

### Baseline tests, before any code change (commit `fdaec4a`, working tree = docs only)
| Suite | Result |
| --- | --- |
| `tests/` | **3904 passed, 2 failed, 214 skipped, 1 collection error** (74 s) |
| `benchmark/tests/` | **58 passed** (0.5 s) |

Command: `python -m pytest -o addopts='' -q -p no:cacheprovider --continue-on-collection-errors --basetemp=D:\t\main tests/`
Known baseline failures (environment, not code changes):
- `tests/test_recall_1192_services.py` collection error: needs `benchmarks/results/test_proj/1192/ground-truth.json` (git-ignored results dir, absent here).
- `tests/test_rule_profiles.py::TestCodeQLSuiteStacking::test_c_language_maps_to_cpp_custom_dir` and `tests/test_stage1_custom_rules.py::TestRunAnalysisExtraSuites::test_missing_extra_suite_filtered_out`: assert `endswith('cpp/suite.qls')` against a Windows `\` path.
Earlier attempts and why they differ: with pytest's default temp dir 523 tests errored (`PermissionError` on `...\Temp\pytest-of-<user>`); with a long `--basetemp` two `test_revpair_pipeline` tests failed with "Filename too long". Use a **short, existing** basetemp (`D:\t`).

### Datasets (outside git, `D:\Project\VulnHunterX\exp-data\datasets`)
| Dataset | Pin | Verified |
| --- | --- | --- |
| BenchmarkJava | `a452b3aafd232245d0753e54eb243d6651f8ef96` (Khoa's audit commit; not in v3.3, awaiting Tuannt, plan §9 #5) | `expectedresults-1.2.csv`: 1023 cases, 531 real / 492 not; sqli 272/232, cmdi 126/125, path 133/135 – exact match |
| Juliet Java 1.3 | zip SHA-256 `d985f4177c2bcd7b03455a05c1c8f2e755f55c9eb250accd052f05f877347e60` (prefix matches plan) | `.java` files: CWE23 724, CWE36 724, CWE78 724, CWE89 3682; `testcasesupport/` present – matches audit |
| Real-Vuln-Benchmark | `90c3221a83e44242b7b67555094349107c21283f` | see RealVuln below |
| ZeroFalse | `3ca00e44840c41cd479efce8b18fbaf8601e99e9` | OpenVuln CWE-22: 5 projects, 29 alerts = 23 true + 6 false; CWE-79: 2 projects, 29 false (out of scope) |
| WebGoat | `38096af4c90d74a770b1162edbd2259fcc03d20a` | equals RealVuln's pinned commit |
| VulnerableApp | `6f5aded1421a3bbd57733f54b6e06c20a75cfd89` | equals RealVuln's pinned commit |
| OpenVuln CWE-22 projects (`openvuln-projects/`) | `buggy_commit_id` from `Projects_info.csv`; also equals the tag commit for all 5 | spark `ce57dfb949`, undertow `4aa98c80fa`, DependencyCheck `c3b5b3c0d7`, zt-zip `bd3f3d77f3`, org.hl7.fhir.core `0b8e2c39841b51def04e29d3b745602517602d5b` |
| RealVuln Java targets (`realvuln-targets/`) | each repo's `commit_sha` from its `ground-truth.json`, fetched with `--depth 1` | 63/63 ok (24 human_authored + 39 llm_generated), HEAD == pinned for all; status in `realvuln-targets/clone_status.json`, script `exp-data/scripts/clone_realvuln_targets.py` |

Sizes on disk: BenchmarkJava 313M, Juliet 388M (plus the 77 MB zip in `_downloads/`), Real-Vuln-Benchmark 498M, ZeroFalse 34M, WebGoat 132M, VulnerableApp 176M, openvuln-projects 497M, realvuln-targets 1.3G. D: had about 96 GB free before the downloads.

Notes:
- hapifhir checkout needs `core.longpaths=true` (one test resource path is too long for Windows); set in that repo's local config.
- First hapifhir attempt used a SHA completed from a 10-character prefix instead of the CSV value, and failed; the final checkout uses the full value from `Projects_info.csv`.

### RealVuln counts (Java, 3 families), recomputed from ground truth
Using RealVuln's own family map (`config/cwe-families.json`: command_injection = CWE-78 **and CWE-77**):
- human_authored: 24 repos, 26 entries (SQLi 18, cmdi 4, path 4). Without WebGoat and VulnerableApp: 20 entries (SQLi 18, cmdi 1, path 1) in 22 repos – matches plan.
- llm_generated: 39 repos, 128 entries (SQLi 32, cmdi 49, path 47) – matches plan **only if the 3 `CWE-77` entries count as command injection** (46 are CWE-78). Plan §3 says "command injection (CWE-78)": the manifest must keep the source CWE and record this mapping.
- Only 6 of the 22 human-authored track repos hold in-scope entries (altoroj, dvja, easybuggy, javavulnerablelab, lamp-cloud, securityshepherd); the other 16 contribute only scanner alerts that the students label.

### Prior-use statement (plan §3.2 / v3.3 §3.2 "Khoa confirms on day 1")

Recorded 2026-11-17 from Khoa's own account given in the working session; Khoa is the author of the statement and Tuannt can contest it.

1. **No tuning run.** No run on OpenVuln or on the RealVuln Java repositories was used to tune, select or change any prompt, policy, question, rule, configuration or code of VulnHunterX. No run result influenced any such choice.
2. **Disclosed harness trials.** Five trial runs on OpenVuln exist in the earlier working clone `D:\Project\VulnHunterX\VulnHunterX` (`benchmarks/results/trial_*`, 12 Nov 2026 UTC). Two made real model calls (`trial_gemini`, `trial_gemini_lite`, on spark, undertow and DependencyCheck); three were dry runs. Their only purpose was to check that the tool and harness run. Khoa states they had no effect on the design, the code or the plans.
3. **This repository** (`exp-implementation`, from commit `0fafb5c`) is the experiment repository. It holds no run output and no results directory.
4. **No RealVuln Java run exists** on this machine.
5. **Handling.** Because the trials were not tuning, the plan's rule "a project used for tuning moves to development" does not trigger. All five OpenVuln CWE-22 projects stay in the real-application track. The paper discloses the trials in one sentence (suggested: "Before the study, the tool was smoke-tested on three OpenVuln CWE-22 projects with a different model; no result from those runs was used to tune the system."). The trial result files in the old clone are kept unchanged as evidence; do not delete them.

### Tree-sitter context for local copies (command checked on a throwaway copy)
`vuln-hunter-x prepare --local-path repos/java/<copy> --name <copy> --lang java --skip-db --backend treesitter` only works if `output/java/<copy>/` already holds a `*.sarif` file; otherwise it prints "No CodeQL databases or source repos found" and still exits 0. With a SARIF present it wrote `functions.csv`, `callers.csv`, `classes.csv` and needed no symlink (copy placed directly under `repos/java/`). Probe copy was deleted.

### Open at the end of Day 1
1. Model and pinned ID, API key (Tuannt). 2. Raw-result storage location (Tuannt). 3. OWASP commit confirmation. 4. Temperature policy (plan §9 #4). 5. Prior-use statement: recorded above. 6. Delivery process of plan §10 (Tuannt).