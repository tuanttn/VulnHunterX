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
## Day 3–4 – Fri 20 – Sat 21 Nov 2026 – P2 Core (run 18 Nov, machine clock)

Status: B2 and B6 coded and tested with mocks; committed as `dea728f` on branch `exp/day3-4-core` (one branch for both items, pushed to `tuanttn/VulnHunterX`; the PR is opened by Khoa, no review yet). No model call (0 runs). Config gate: B2 passed; B6 coded with temperature as a parameter only. The temperature (plan §9 #4) does not block the merge; it blocks real model runs, which the harness refuses without a stated value.

### B2 – harness and engine
- `entry_to_finding`: `cwe_ids` normalised with `sarif/parser.py:_normalize_cwe` from `metadata.cwe_ids`, `metadata.cwe_tags_raw` and `cwe_id`; raw tags kept in `Finding.tags`; `metadata.dataflow_path` (manifest steps `{file, line, message?}` or SARIF strings) → `Finding.dataflow_path` as `line N (file): message`.
- Missing context: new `verification.require_repo_context` (default off for the CLI) turns both snippet-fallback sites in the engine into an Error verdict (`decision_source=context_gate`); `ContextProvider.missing_context_files` checks all three CSVs, not only the directory. `vulnhunterx-repo` option `require_context` (default `true`) fails before building the engine and records `context_path`.
- `--repeats N` / `--condition LABEL`: checkpoint `<dataset>_<approach>_<route>_<condition>_r<k>_results.json`, fresh approach per repeat, `run_id` per alert and repeat, labels in `result_metadata` and `findings.jsonl`; old names when neither flag is passed.
- `BenchmarkResult.result_metadata` (serialized as `result_metadata`, separate from the entry's `metadata`): route, decision source, policy record (family, terminal reason, facts), end reason, confidence, iterations, context path, run settings.
- Found while reading the code: the harness always injects `max_iterations=10` unless `--approach-option max_iterations=…` is given; the policy path already forces `force_decision=False`; `--nmd-handling fp` would turn unresolved into FP (use the default `exclude`).
- Manifest check (now `scripts/exp/b2_manifest_routing.py`, see "Risk follow-up"): all **809/809** OWASP manifest alerts → exactly one policy via `entry_to_finding`: `sql_injection_java` 479, `command_injection_java` 131, `path_access_java` 199 (same as day 2); no excluded rule in the manifest.

### B6 – model client
- `LLMClient(temperature=None)` sends no temperature; `seed=None` sends no seed (already supported). Defaults unchanged (0.0 / 42) for the CLI. `vulnhunterx-repo` options `seed` and `temperature`: `default | none | <number>`.
- New `llm/call_log.py`: one JSONL record per completion from `LLMClient._completion` (run ID, entry ID, repeat, condition, route, requested and **returned** model ID, litellm version, tokens incl. cached, latency, finish reason, parameters sent, litellm cache flag). No prompt or response text; errors keep type and status code only. Harness default: `<run_dir>/llm_calls_<dataset>_<run name>.jsonl` (not in dry runs). `run_config.json` records the client version, `drop_params` and the cache flag.
- One engine and one `LLMClient` per verified alert (separate session); `models_returned` in result metadata.
- Limit: `litellm.drop_params=True` stays; the log shows parameters sent, not what the provider accepted.

### Audit pass (same day, after the first full run)
Found and fixed: (1) `single-shot-cwe` (the single-call method) built its own `LLMClient`, still sent seed 42 / temperature 0.0 and had no call log; it now takes `seed`, `temperature`, `call_log`, builds one client per entry and records `models_returned`. (2) The preflight call was not logged (now `llm_calls_preflight.jsonl`). (3) The harness did not check `litellm.cache` (now exits 2 on a real run when it is on). (4) A `config.md` table cell contained bare `|` characters. (5) No test drove the real engine: added `tests/test_exp_b2_b6_integration.py` (real engine + real policy registry + real client, mocked `litellm.completion`). Mutation check: blanking `cwe_ids` in `entry_to_finding` makes 7 tests fail.

### Checks
- New tests: `tests/test_exp_b2_entry_finding.py`, `test_exp_b2_engine_context.py`, `test_exp_b2_repo_context.py`, `test_exp_b2_repeats.py`, `test_exp_b2_b6_integration.py`, `test_exp_b6_model_client.py` (see the final count below); `tests/test_approach_repo_context.py` updated (fixtures now provide context CSVs).
- Full `tests/` (CodeQL not on PATH, as for the day-1 baseline), first run: **3955 passed, 2 failed, 214 skipped, 1 collection error**; final count after the audit and the risk follow-up is in "Risk follow-up" (baseline 3904 / same 2 failures / same collection error; this tree lacks the 22 day-2 tests of PR #2). `benchmark/tests/`: 58 passed. `ruff check`, `ruff format --check src/`, `mypy src/`, `git diff --check`: clean (one B904 in `run_benchmark.py` exists at HEAD).
- Note: with `env.ps1` active, CodeQL is on PATH and `tests/test_custom_codeql_queries.py` compiles every query (the full suite then runs far beyond 10 minutes). Compare with the baseline with CodeQL removed from PATH.

### Risk follow-up (same day; items numbered as in the list of remaining limits)
Result: items 1, 2 (log part), 4 and 6 done; item 3 analysed offline, re-baselining deferred; items 5 and 7 open. No model call (0 runs).

**1. Real runs without `seed=none` (done).** `run_benchmark.py` now exits with code 2 for an experiment run (`--repeats` or `--condition`, not `--dry-run`) when an approach that has a `seed` option (`vulnhunterx-repo`, `single-shot-cwe`) is left at the default, i.e. the client's built-in seed 42. A fixed number is accepted with a warning. Runs without the repeat flags and dry runs are not guarded, so other users of the harness are unchanged. Tests: refused with the option missing or `default`; allowed with `none`; dry run and non-experiment run unaffected. Not guarded: temperature (still waiting for Tuannt, see below).

**2. drop_params and retries.**
- Done (log part): every call record now has `params_sent.names`, `params_sent.num_retries_configured` and `params_outside_litellm_supported_list` (sent parameters absent from litellm's supported list for that model; `null` when litellm does not know the model). Example from the tests: `seed` sent to `anthropic/claude-sonnet-4-20250514` is listed, because litellm's list for Anthropic has no `seed`. The list is litellm's static table, so it shows a likely drop, not what the provider received.
- Limit to state (not fixable here): one log record is one `litellm.completion` call. litellm's own retries (`num_retries`, default 1 from `LLMConfig`) happen inside that call; they are not visible, so tokens and latency in the record are those of the final attempt and billed usage can be higher. The configured retry count is logged. A rate-limit rotation of keys (Ollama/Gemini pools) is also invisible.
- Before publishing numbers: compare the provider's billed usage with the logged tokens, and report any run whose calls list a parameter in `params_outside_litellm_supported_list`.

**3. Datasets whose route changed (analysed; re-baselining not done and not possible yet).** `scripts/exp/b2_route_impact.py` computes, without a model, the route of every entry before B2 (no CWE ids) and after. On the 10 bundled fixtures (91 entries, small samples of each dataset, not the full data) 18 entries change route, in six datasets: `cvefixes-diff` (php CWE-89 → `sql_injection`; python CWE-89 → `sql_injection_python`), `juliet-java` (CWE-89 → `sql_injection_java`), `owasp-java` (CWE-89 → `sql_injection_java`), `realvuln` (python CWE-89 → `sql_injection_python`), `secllmholmes` (python CWE-78 → `command_injection_python`, CWE-89 → `sql_injection_python`) and `security-rules` (php CWE-98 → `path_access`; python CWE-502 → `deserialization_python`). Unchanged: `castle`, `diversevul`, `juliet` (C), and every entry whose CWE no policy owns. Only approaches that call `entry_to_finding` are affected (`vulnhunterx`, `vulnhunterx-repo`, ablations); `raw-sast` and `single-shot-cwe` are not. Any number produced for these datasets before B2 (for example in older clones or papers) is not comparable with a run after B2. Re-running those baselines needs real model calls, so it is **not** done now: the config gate allows real calls only on days 9, 10–11 and 13–16 and only when the user asks for that run, and no model, key or temperature is fixed yet (plan §9 #1, #4). It is also not needed for the validity of the experiment: every number the paper reports is produced after B2 (OWASP, Juliet dev, real-application and AI tracks all run through the manifests and the B2 code), and nothing produced before B2 may be reported (v3.3 §5.1). It matters only for comparing with older numbers (the July run, the old-clone trial runs, other papers), which v3.3 already excludes. A result file written before B2 has no `result_metadata`; a file written after B2 has it with `decision_source`, so the two cannot be pooled by mistake. If a pre/post comparison is still wanted, it needs the user's explicit request, a pinned model and a budget; the dataset list above is the scope. The fixture counts are a lower bound: run the script on the full exported entries of each dataset before choosing what to re-run.

**4. Manifest contract and label leakage (done) and a limit.**
- `MODEL_VISIBLE_METADATA_KEYS` (`message`, `cwe_ids`, `cwe_tags_raw`, `dataflow_path`) and `ROUTING_METADATA_KEYS` (`repo_name`, `lang`) in `benchmarks/approaches/base.py` are the only metadata keys the harness reads. `tests/test_exp_manifest_contract.py` records every key read through a spying dict: `entry_to_finding` and `vulnhunterx-repo` stay within the lists, so adding a read of `label`, `source_case` or another field fails the test (checked by mutation: reading `label` into the message fails 3 tests). The reference row → entry mapping (`manifest_row_to_entry` in `b2_manifest_routing.py`) copies only the allow-listed fields and never the row label; changing a row's label changes nothing a model can see. `tests/test_exp_b2_b6_integration.py` sends an entry whose id, function name, snippet, label and metadata carry a sentinel through the real engine and checks every message passed to `litellm.completion` and every field of the call log (except the by-design `entry_id`): no sentinel; a control sentinel in the allowed `message` does appear. The B3c adapter must use the same two lists.
- Limit to state: the manifest stores a data-flow step as file and line only, no step message. A scan from the CLI gives the model steps such as `line 12: request.getParameter(...)` and, from the first step, a source-kind note (remote or operator input). In benchmark runs the steps are `line 12 (file)`, so the model sees where the flow runs but not what each step is, and the source-kind note cannot fire. The two variants see the same text, so the comparison is not biased, but absolute rates are not those of a CLI scan. Say so when describing the system; changing it means re-scanning with step messages (B3a).

**5. Handoff with an Error verdict (done).** `tests/test_exp_handoff_error.py` (9 tests). Findings: (a) the Java families have no `handoff_from` (`path_access_java` is a primary owner), so the Java experiment never runs the handoff combiner; only PHP, C#, Go, JavaScript and Python families do. (b) The combiner treats an Error verdict as an unresolved handoff. Error on both routes returns the handoff's Error; handoff Error with base False Positive returns the Error, so a failed handoff can never be turned into a dismissal by the base route; handoff Error with base True Positive keeps the True Positive; an applicable handoff FP followed by a base Error returns the base Error. (c) Real path with the B2 context gate on both routes (policy and legacy, real `_verify_policy_finding`): one Error verdict, `decision_source=context_gate`, no model call, also through `verify_findings`. The combiner docstring says "Needs More Data" for an unresolved handoff; an Error is returned as an Error (the harness records it as ERROR and the run is retried or excluded and counted), which is a non-dismissal either way. No code change was needed. Mutation check: letting the base FP override an unresolved handoff fails 5 of the 9 tests.

**6. Routing script in the repo (done).** `scripts/exp/b2_manifest_routing.py` (with an empty `scripts/exp/__init__.py`, same as PR #2) checks that every manifest alert resolves to exactly one family, that no excluded rule is present and, with `--expect FAMILY=N`, the counts. Exit 0 / 1 / 2. On the OWASP manifest: 809 entries, `sql_injection_java` 479, `command_injection_java` 131, `path_access_java` 199, exit 0. It reads no label (placeholder entry label, test checks the source). Command: `python -m scripts.exp.b2_manifest_routing ../exp-data/work/shopapp-java/manifest.jsonl --expect sql_injection_java=479 --expect command_injection_java=131 --expect path_access_java=199`.

**7. B6 merge (waiting).** Blocked until Tuannt decides the temperature (plan §9 #4); until then the experiment commands carry a placeholder for `temperature`.

Checks after the follow-up: full `tests/` (CodeQL not on PATH): **4020 passed, 2 failed, 214 skipped, 1 collection error** (baseline 3904 passed with the same 2 failures and the same collection error; +116 tests, none failing; count after the completeness review and the temperature check). `benchmark/tests/`: 58 passed. `ruff check` (src, scripts/exp, benchmarks/approaches, new tests), `ruff format --check src/ scripts/exp`, `mypy src/`, `git diff --check`: clean; the only ruff finding is the B904 in `run_benchmark.py` that exists at HEAD. Mutation checks: blanking `cwe_ids` fails 7 tests; reading `label` into the message fails 3; letting a base FP override an unresolved handoff fails 5.

### Completeness review (end of Day 3–4)
Checked every "Xong khi" of B2 and B6 (plan §6), the day 3–4 checklist (plan §7, config §3) and the places where a default of the harness differs from the fixed configuration. Two things were still open and are now fixed:
- **Guard for all fixed settings, not only the seed.** The harness defaults were wrong for the experiment in more than one place and relied on whoever typed the command: `--model` fell back to `gpt-4.1` (the model is a decision of the study, plan §9 #1), `--provider` to `openai`, `max_iterations` to 10, forced choice stayed on, `require_context=false` re-enabled the snippet fallback, and `--nmd-handling fp` would score an unresolved run as a False Positive, and a missing temperature silently sent the client's 0.0. An experiment run (`--repeats`/`--condition`, no `--dry-run`) now exits with code 2 and lists every missing or wrong item at once (`_experiment_config_problems`; the temperature must be stated as `none` or a number, the harness does not pick it, plan §9 #4); `max_iterations` other than 5 and a fixed seed are only warned. Dry runs and runs without the repeat flags are unchanged. `--model`/`--provider` are resolved after parsing so "chosen" can be told from "fallback"; an `LLM_MODEL`/`LLM_PROVIDER` environment variable counts as chosen. Tests: 20 new in `tests/test_exp_b2_repeats.py` (full configuration accepted; each missing or wrong item refused, temperature included for both approaches; all reported together; dry run exempt). Mutation check: disabling the temperature check fails 5 tests.
- **Report generation with the new checkpoint names.** `main()` swallows a report failure into a warning, so the earlier tests could not show it. Checked directly: three repeats in one run directory produce `REPORT.md`, `summary.json` and charts without error; each repeat is its own row (`vulnhunterx-repo_auto_full_r1..r3`); the generated "best F1" line compares rows and is not the experiment analysis (B5).

Status against the checklist: all items of plan §7 day 3–4 are done and tested with mocks except the temperature, which waits for Tuannt. What day 3–4 still lacks is delivery, not code: no branch, commit or PR exists (Khoa's choice), PR #1 and #2 are unreviewed, so the config gate's rule "a PR that changes a configured value updates `config.md` and records the gate result in the PR description" is met in the files but not yet in a PR. Delivery decision (Khoa, after the entanglement check): **one branch `exp/day3-4-core` and one PR** for B2 and B6 instead of two, because `run_benchmark.py` (about 50 B2 / 28 B6 lines), `repo_context.py` (16 / 33) and the repeat tests are interleaved and B6 would branch from B2 anyway. This deviates from "one PR per build item" (CLAUDE.md, plan §10.1; §10 is still Khoa's proposal pending Tuannt, §10.5 #1) and goes in "Lệch so với plan" of the daily report; precedent: `exp/day2-data-prep`. The PR description keeps one "Xong khi" list per item and a file → item map. Temperature does not block the merge (B6 only adds a parameter and picks no value); it blocks real model runs, which the harness now refuses without a stated temperature. Order: PR #1 (docs) first, because `exp-implementation` has no `config.md`/`plan.md`; then branch from the updated `exp-implementation`. Still to write: the PR description (plan §10.1 template) and the day 3–4 daily report.

### Open at the end of Day 3–4
0. New since the follow-up: re-baseline decision (item 3: only if a pre/post comparison with old numbers is wanted, needs an explicit run request and a pinned model), billed-versus-logged token check (item 2) before any number is published. The handoff test (item 5) is done.
1. Temperature (blocks real runs and the freeze, not the merge). 2. Model + pinned ID, key. 3. Open the PR for `exp/day3-4-core` (`dea728f`); review/merge it together with PR #1 and #2 before day 5 starts. 4. Earlier open points (OWASP commit, 488 genuine alerts, storage) unchanged.
