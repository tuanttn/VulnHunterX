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

## Day 2 – Thu 19 Nov 2026 – P1 Data (run 17–18 Nov, machine clock)

Status: OWASP copy, scan and manifest done; development copies scanned and counted. No model call (0 runs). Code: branch `exp/day2-data-prep`, commit `9de3003`, draft PR #2 into `exp-implementation` (scripts under `scripts/exp/`, tests under `tests/test_exp_*.py`). Nothing in `src/` or `benchmarks/` changed. Outputs (copies, name maps, label map, SARIF, manifest) stay outside git under `exp-data/work/<copy>/`, `repos/` and `output/`; this file records hashes.
Config gate: passed. Open: OWASP commit `a452b3a` is used **provisionally** (Tuannt has not confirmed it, plan §9 #5); re-run B3b and B3a if he picks another.

### B3b – renamed OWASP copy (`repos/java/shopapp-java`)
- Source BenchmarkJava `a452b3aafd232245d0753e54eb243d6651f8ef96`, `src/main/java` only, without the three `report` files: 2763 files (2740 test cases, 23 helpers). No expected results, metadata, git history or resources.
- Every comment blanked (line numbers kept). `BenchmarkTestNNNNN` → random token (file, class and strings); `org.owasp.benchmark` → `com.acme.app`; the sub-packages `helpers`, `testcode`, `service` → neutral names derived from the seed (`ma6b65f`, `m18b4f2`, `mb6dbe9`; their own sub-folders such as `entities`, `filters`, `pojo` are unchanged); servlet paths → `/svc/<token>`; `benchmarkprops`, `benchmark.properties`, `Problem executing … TestCase` strings. `org.owasp.esapi` kept (whitelisted).
- Reading of v3.2 B3b: v3.3 §5.2 says "As v3.2"; v3.2 says "the package and folder names `org.owasp.benchmark` (including `helpers` and `testcode`) with neutral names". The sentence has two readings (prefix only, or sub-package names too). Khoa chose the strict one (sub-packages renamed). B3b and B3a were run twice (first prefix only, then strict); counts, alert set, toolchain and the 30% figure are identical, only paths and hashes differ. Hashes of the first run: `exp-data/work/_prev_readingB/`. Class names such as `DatabaseHelper` and `ThingFactory` are unchanged (v3.3 does not ask for it).
- Checks: case-insensitive leak search (`owasp|benchmark|test ?case|expectedresults|real vulnerability|sqli-|cmdi-|pathtraver|problem executing`) = 0 outside `org.owasp.esapi`; independent grep agrees; no directory or package named `helpers`/`testcode`/`service`; no file gained a parse error; every `com.acme.app.*` import resolves to a file; line count per file equals the source; no token collision; two builds with the same seed give the same tree hash.
- Left in the helpers of the original code (not labels of single cases): `insecureCmd.sh/.bat` (3 places in `Utils.java`) and `unsafe-inline` in a CSP header.
- Seed `vhx-owasp-v33-seed1`. Tree SHA-256 `42235aee3cd8e6f5bc9985965948b100e98019f2adfb6fcee8601b8da9989754`; `name_map.json` `51ba17d77eae2a9504beaa380f3d0de4450cd6b00f7204f596642d819c4eccc5`.

### B3a – CodeQL scan and manifest (OWASP)
- CodeQL CLI 2.27.4; `codeql/java-queries` 1.12.0; `codeql/java-all` 9.3.4; `codeql/threat-models` 1.1.1. Suite `java-security-extended`, `--build-mode=none`, CLI called directly.
- Probe on 60 files (20 per family) before the full scan: taint-flow alerts with `codeFlows` appear (`java/sql-injection` 14/14, `java/path-injection` 16/16, `java/command-line-injection` 8/8). Build mode none loses no taint source in this setup. This closes the day-1 open check.
- Full scan: **4163 alerts**, **2680 with `codeFlows`**; 3295 outside the three families; 59 `java/exec-tainted-environment` excluded and counted (`java/relative-path-command`: none in OWASP).
- Manifest (one alert per test case, rule with a data-flow path preferred, rule recorded): **809 entries = 488 genuine + 321 false alarms**. ZeroFalse reports 868 (531 + 337). The whole gap is the excluded rule: 531 − 488 = 43 and 337 − 321 = 16, together 59. These cases have no other alert. Not compared alert by alert with the ZeroFalse SARIF.

| Family | Genuine alerts / cases | False alarms / cases | Genuine cases without alert | False cases without alert |
| --- | --- | --- | --- | --- |
| SQLi | 272 / 272 | 207 / 232 | 0 | 25 |
| Command injection | 83 / 126 | 48 / 125 | 43 | 77 |
| Path traversal | 133 / 133 | 66 / 135 | 0 | 69 |
| **Total** | **488 / 531** | **321 / 492** | **43** | **171** |

- Share of genuine alerts whose data-flow path leaves the method that contains the sink (any step in another file, or outside that method's lines; definition set by Khoa, v3.3 does not define it): SQLi 200/272 (73.5%), cmdi 61/83 (73.5%), path 96/133 (72.2%), **total 357/488 = 73.2%**. Gate (≥ 30%) passed, so function-only stays a candidate. Every genuine alert has a data-flow path. Checked by hand on two samples (one leaving, one not).
- All 809 entries resolve to exactly one policy: `sql_injection_java` 479, `command_injection_java` 131, `path_access_java` 199 (no overlap error).
- Context (tree-sitter): 7515 functions, 72296 callers, 3643 classes.
- Hashes: SARIF `47235d8c145f0f4da642109d12509e3896921716eb0ef04303f3727f2b6ebecc`; `manifest.jsonl` `88ea0d48f965c6cc095d7379d5c44fe872c3696d2f204153f7bbf300af083bfa`.
- The manifest has the fields `source_case` (original test name) and `label`. It stays outside the copy; the B3c adapter must not pass these to anything the model reads (v3.3 §3.6).

### Development tier
- **Juliet Java 1.3** (`repos/java/suite-java`): CWE89, CWE78, CWE23, CWE36 (5854 files) + `testcasesupport/` (10) = 5864 files. Label map made before any edit from the line ranges of every `bad*` and `good*` method; file-name rule for `_81_bad` / `_81_good*`; 5854 cases; three files checked by hand. On-disk redaction, consistent across the repo: comments blanked; methods `bad*`/`good*`, classes, files and folders containing `CWE…`, and `testcases` renamed; `Benign, fixed string` replaced. Leak search = 0. Seed `vhx-juliet-v33-seed1`. Because `AbstractTestCase` declares `bad`/`good`, each replaced name still stands for one label across the repo (consistency required by v3.3).
  Hashes: tree `91332a1a270a288b38e5cfa0ee50520bb6832fe04572de1c03b7b1a2b97058d1`, `name_map.json` `8c591bd8dbdf73d03a707353573319703db83fd279e65721b73ba7cc037cfc62`, `label_map.json` `515478a5339656844600a3826c3ac429dbde1c5c707c50c99a2eb7dc29bbe1f1`, SARIF `168b93e43f91871dfda98243579f4dd85f4f52ffe9187ebf4dae7a40acd0b7a8`. Context: 25820 / 196499 / 5960.
- **WebGoat `38096af`, VulnerableApp `6f5aded`**: copies without `.git` (tree `5a809dc105e04db5e05935e093774e31465e8b5b667607aff57063f21bd88c80`, `d3911643b79171a7a00b9f65c2736b9c440101cd5b8b946abf7920c4af23ce87`); SARIF `7db898c0b551ce0d4bc8f1388203d0401d966c4bc73170bc7541f2ae788878b5`, `620ec261e8408b12f60424d7c7079ab2b285c1a64213357badce708d2b870f15`. Context (functions / callers / classes): 1388 / 10998 / 434 and 1370 / 8578 / 173.

Alerts by source × family × label (Juliet by `bad`/`good` line range; apps: genuine = matches a RealVuln entry with the same file, line range and family; other alerts are unlabelled, not false alarms):

| Source | Family | Genuine | False alarm | Unlabelled |
| --- | --- | --- | --- | --- |
| Juliet | SQLi | 2220 | 1140 | – |
| Juliet | cmdi | 444 | 240 | – |
| Juliet | path (CWE23 + CWE36) | 1332 | **36** (in 12 files) | – |
| WebGoat | path | 1 | – | 15 |
| WebGoat | SQLi | 0 | – | 16 |
| VulnerableApp | cmdi | 2 | – | 0 |
| VulnerableApp | path | 1 | – | 4 |
| VulnerableApp | SQLi | 0 | – | 11 |

- Juliet: 81 alerts outside the three families were left out; none lies outside both `bad*` and `good*`. VulnerableApp: 2 `java/relative-path-command` alerts excluded and counted.
- RealVuln entries in the three families: WebGoat cmdi 1 and path 2 (path 1 flagged, cmdi not); VulnerableApp cmdi 2 and path 1 (all flagged). Neither app has a SQLi entry.
- Pooled rule (v3.3 §2: fewer than 20 development false alarms in a family → the "Decided share" check is computed on the three families pooled): the path family has 36 false-alarm alerts but only 12 cases. By cases (one alert per case, as the development manifest will do) it is below 20, so the pooled rule is likely to apply; by raw alerts it is not. Decided when the development manifest is built (B3c, 100 cases per family); handwritten cases and student labels may add false alarms.

### Checks
- Full `tests/`: 3926 passed, 2 failed, 214 skipped, 1 collection error (day-1 baseline: 3904 passed, same 2 failures, same collection error). 22 new tests, no new failure. `ruff check` and `git diff --check` clean.
- Commands (from the repo root after `. ..\exp-data\scripts\env.ps1`): `python -m scripts.exp.b3b_owasp_copy --benchmark-dir <BenchmarkJava> --pin a452b3aafd232245d0753e54eb243d6651f8ef96 --out repos/java/shopapp-java --work-dir <exp-data>/work/shopapp-java --seed vhx-owasp-v33-seed1 --force`; `python -m scripts.exp.b3a_scan_manifest scan …` and `… manifest …`; `python -m scripts.exp.dev_data_prep juliet|app-copy …`; `python -m scripts.exp.count_dev_alerts …`; `vuln-hunter-x prepare --local-path repos/java/<copy> --name <copy> --lang java --skip-db --backend treesitter` for the four copies.

### Open at the end of Day 2
1. OWASP commit confirmation (provisional `a452b3a`). 2. Accept 488 genuine alerts instead of 531 (the excluded rule `java/exec-tainted-environment` removes 43 genuine and 16 false-alarm command-injection cases). 3. Pooled rule: confirm when the development manifest is built. 4. Model and pinned ID, API key, temperature, storage location (needed before B2/B6, day 3–4). 5. Not built yet: development manifest and the Juliet sample (100 cases per family, at least 50 genuine); labels for the WebGoat/VulnerableApp alerts that match no ground-truth entry.