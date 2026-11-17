# VulnHunterX: experiment plan (v3.3, final)

17 November 2026. Authors: Tuannt, Thientc, Khoa. Khoa implements and runs it, with student help.

This plan replaces v3.2 (16 November). It settles the three things that were open: Khoa's review of v3.2, the dataset proposal from our chat, and how we pay for model runs. Plan v3.1 stays the reference for every term, test and rule that this plan does not change; read its section 2 first. Where v3.2 and this plan differ, this plan wins.

Code state: branch and `main` are both at commit `0fafb5c`, the commit Khoa audited. Nothing in his audit has been fixed yet. No experiment has been run for this plan.

## 1. What we decided (17 November)

| # | Topic | Decision |
| --- | --- | --- |
| 1 | Main test | OWASP Benchmark Java v1.2 carries the hypothesis tests. It is the only set with enough labelled cases (section 3) |
| 2 | Real applications | A second, pre-specified track: human-written Java applications from RealVuln and the CWE-22 projects of OpenVuln. Reported with intervals. No significance claim |
| 3 | AI-generated code | A third, descriptive track: the Java repositories that RealVuln marks `llm_generated` |
| 4 | Scope | Java, CodeQL, three families: SQL injection (CWE-89), command injection (CWE-78), path traversal (CWE-22). No Python in this paper |
| 5 | Development data | WebGoat, VulnerableApp, a Juliet Java sample, and handwritten false-alarm cases. pygoat is dropped because it is Python |
| 6 | Model access | Existing subscriptions only, through a headless CLI. No API spending, no hiring. This cancels "the API fee is not a limit" in v3.2 |
| 7 | Khoa's five requests | All accepted (section 2) |
| 8 | Results storage | Raw results stay outside git. We commit only hashes |
| 9 | Carried over from v3.2 | No public registration; freeze and hash before test runs. Target: JSS "New Ideas and Trends Paper", EMSE PROMPT-SE as fallback. Declare AI-assisted writing. Failure analysis in the small form |

Still open, and who closes it:

- The one model and its pinned ID: Tuannt, on day 1.
- Corresponding author: Tuannt and Thientc, before submission.
- Venue rules and deadlines were not rechecked for this plan: Tuannt, before writing starts.

## 2. Answers to Khoa

| Khoa's point | Answer |
| --- | --- |
| Give prompt-only all the evidence rules | Yes. The prompt-only variant gets every fact, the decisive facts, the verdict table and every admissibility rule as text, including "a comment is not evidence". The two variants then differ only in the two code steps: the evidence check and the computed verdict |
| Reject comment-only citations (changes C2) | Yes. A citation must quote the code line. The check confirms that the line is in the retrieved slice and is not a comment. The same rule is written into the prompt-only text. We state the limit in the paper: the check proves the line exists, not that it supports the claim |
| No-requirements variant in the hard condition | Yes, one run per alert. In that condition the legacy path's prefetch, repository signals and reachability check are restricted like everything else, so it has no side channel |
| RQ1 says "existing methods" | Narrowed. See section 4 |
| C1 says scanner-independent and multi-language | Reworded. The system supports three scanners and eight languages; we evaluate Java with CodeQL. The paper says which is which |
| Blank comments in the datasets | Yes, for OWASP and Juliet, keeping line numbers. In the misleading-comment condition the inserted comment is then the only one |
| `org.owasp.esapi` | Keep it. It is a real sanitizer library. The leak search whitelists it. Also rename `benchmarkprops`, the `@WebServlet` paths and the `"Problem executing cmdi - TestCase"` string |
| Fewer than 20 development false alarms in a family | Compute the "Decided share" check on the three families pooled, and report that family's count next to it. Handwritten cases may fill the gap (section 3.4). The test families never change |
| Results in git or not | Outside git, as `docs/GIT_WORKFLOW.md` requires. Commit `freeze.sha256` and the hashes of the result files |
| JSS 113040 | Khoa's reading is that it does not overlap. We keep the direction. Before submission Khoa writes a one-page comparison with 113040 and v3.1 sources [19] and [20], and we cite from the full texts |

The code blockers in audit section B (missing CWE on the `Finding`, silent fallback to snippets, uncovered rules, CWE format, fixed seed, missing returned model ID, missing result metadata, uneven iteration limits, no repeats) are all accepted as build work in section 5.

## 3. Data

Counts below come from the dataset files at the pinned revisions. They are ground-truth entries, not CodeQL alerts. The alert counts come from our own scan on day 2.

### 3.1 Main test: OWASP Benchmark Java v1.2

1,023 cases in the three families: 531 genuine, 492 not vulnerable (SQLi 272/232, command injection 126/125, path traversal 133/135). ZeroFalse reported 868 CodeQL alerts on them (531 genuine, 337 false alarms). Our scan uses build mode none and may give another count; we report it.

Preparation is B3b and B3a of v3.2 with the changes in section 2. If subscription capacity cannot cover every alert, we test a sample drawn with a fixed seed, stratified by family and label, with at least 300 genuine alerts. The sample size is fixed at the freeze, before any test run (section 6).

### 3.2 Real-application track

| Source | Pinned revision | What it gives in our three families |
| --- | --- | --- |
| RealVuln 3.1.0, Java, `human_authored` | `kolega-ai/Real-Vuln-Benchmark` at `90c3221` | 24 repositories, 26 genuine entries (SQLi 18, command injection 4, path 4), no labelled false alarms |
| OpenVuln (ZeroFalse), CWE-22 projects | `mhsniranmanesh/ZeroFalse` at `3ca00e4` | 5 projects, 29 CodeQL alerts: 23 genuine, 6 false alarms |

Rules for this track:

- WebGoat and VulnerableApp are RealVuln repositories. We use them for development, so they leave this track. That removes 6 genuine entries and leaves 20 (SQLi 18, command injection 1, path 1) in 22 repositories.
- RealVuln labels vulnerability locations, not scanner alerts. We scan each repository at its pinned commit with the same CodeQL version and suite. An alert that matches a ground-truth location (same file, overlapping lines, same family) is genuine. RealVuln Java has no false-alarm labels, so every other alert in the three families is labelled by two students working independently from the code, without seeing model output; Tuannt resolves disagreements. We report raw agreement. Alerts they cannot settle are left out and counted.
- OpenVuln ships SARIF and labels but no checkouts. `Projects_info.csv` gives the repository, tag and vulnerable commit of each project, so we check them out from upstream. If a checkout cannot be reproduced, that project is left out and named. The two CWE-79 projects (29 alerts) are out of scope.
- We keep the source CWE, the scanner's CWE tags and our family side by side in the manifest, with a reason for every mismatch or exclusion. We never overwrite a source label.
- Prior use: the repository has an OpenVuln adapter but no policy, prompt or test tuned on its alerts. Khoa confirms on day 1 that no local tuning run used OpenVuln or the RealVuln Java repositories. Any project that was used moves to development.
- Wording: all RealVuln targets are intentionally vulnerable applications. We call them "human-written applications", not production software. Only the OpenVuln projects are production code with CVEs.

With at most about 43 genuine alerts, this track cannot carry a hypothesis test: it would need a difference of roughly 17 points. We report rates with 95% intervals and say plainly that it is a check of direction.

### 3.3 AI-generated track

RealVuln Java, `llm_generated`: 39 repositories, 128 genuine entries in the three families (SQLi 32, command injection 49, path 47), no labelled false alarms. Enforced and prompt-only, full context, one run each, on alerts that match a ground-truth location. Wrong-dismissal rate only. Descriptive, kept apart from the human-written results.

### 3.4 Development

- WebGoat (`38096af`) and VulnerableApp (`SasanLabs/VulnerableApp` at `6f5aded`), scanned and labelled as in section 3.2.
- Juliet Java 1.3 sample as in v3.2 section 3.3, with the audit's corrections: label map from the line ranges of every `bad*` and `good*` method, file-name rule for `_81`, CWE-23 and CWE-36 added, hints removed on disk, `testcasesupport/` copied.
- Handwritten false-alarm cases. A case counts only if CodeQL flags it in one of the three families and two reviewers agree it is safe. They are stored with their own provenance tag and never enter a test track.
- On day 2 we count development alerts by source, family and label. Development data is for smoke, pilot, the one tuning round and the freeze checks. Nothing from it is reported as a result.

## 4. Contributions and questions

**C1. The VulnHunterX system.** A four-stage pipeline (`prepare → analyze → verify → report`) that takes CodeQL, Semgrep or OpenGrep alerts through rule-specific questions, repository-scoped code retrieval, typed evidence and family evidence policies, for eight languages. This describes what is built. What we measure is Java with CodeQL in three families, and the paper keeps the two apart.

**C2. Requirements enforced in code against the same requirements in a prompt.** Both variants get the same facts, table, rules, retrieval and budgets. Only the evidence check and the computed verdict differ.

**C3. A reproducible evaluation.** Manifests, prompts, policies, logs, analysis code, and the labelled alert set of the real-application track.

- **RQ1.** On OWASP Benchmark Java alerts from CodeQL, how many false alarms does the enforced system remove and how many genuine alerts does it wrongly dismiss, next to the prompt-only variant, the no-requirements variant and a single model call?
- **RQ2 (H2).** In a hard condition, does the enforced variant wrongly dismiss fewer genuine alerts than the prompt-only variant?
- **RQ3 (H3).** Is that difference larger in the hard condition than at full context?
- **RQ4.** Do the rates point the same way on human-written applications, CVE projects and AI-generated code? Descriptive only.

Claims cover the tested alerts as a fixed set, one model, three families. H1 (comparison with a coding agent) is not tested.

## 5. Experiments: done and to do

### 5.1 Done

- The system and the three Java policies exist with deterministic tests. Their verdict quality is unmeasured.
- The July run (125 alerts, PHP/C/C++/JavaScript) predates the first evidence policy. It is development history, not a result for this paper.
- The six simulation outputs under `journal-evidence/` are planning evidence for the tests, not measurements.
- Khoa's audit was read-only. Its test counts (851 collected, 106 import errors) describe a missing environment, not a test result.

### 5.2 Build items

B1–B5 are those of v3.2 section 3.2, changed as listed. B0, B6 and B7 are new.

| Item | Work | Done when |
| --- | --- | --- |
| B0 | Environment: Python 3.12 venv with the repository's dependencies, pinned CodeQL CLI and JDK. Run the existing suite before any edit | Pass/fail counts recorded |
| B2 | `entry_to_finding` passes CWE IDs (normalized to `CWE-89` form, original tags kept), message and data-flow path. `--repeats`, with repeat and condition in the run name. Iteration limit 5 and no forced choice for every variant; a run that ends without a verdict is recorded as unresolved, never as False Positive. Missing repository context is an error, not a fallback to snippets, and the context path used is logged. Result metadata: `decision_source`, facts, end reason, confidence | An SQLi entry resolves to `sql_injection_java` and its metadata says `policy`. Every manifest alert resolves to a policy; `java/exec-tainted-environment` and `java/relative-path-command` are left out of the manifests and counted |
| B6 | Subscription backend: a client that sends each model call to the headless CLI as a plain completion, with tools off, an empty working directory, no memory and no cache. Per call it logs the CLI version, the model ID the CLI returns, tokens and a run ID. The CLI offers no seed and we do not assume a temperature setting; repeats rely on natural variation | Two repeats of one alert are separate sessions. The log has the returned model ID for every call. Mocked in default tests |
| B3b, B3a, B3c | As v3.2, with section 2. One alert per test case: prefer the rule with a data-flow path, and record the rule chosen. Manifest paths use `/`. No redaction rule on the manifest dataset. The adapter fills `code_snippet` for the single call | Leak search finds nothing outside the whitelist; files parse; entry count equals manifest lines |
| B7 | Real-application and AI-track manifests (sections 3.2, 3.3): checkouts at pinned commits, scan, location match, labelling sheet for the students, mismatch list. Tree-sitter context extracted for every copy | Counts by source, family and label. Every exclusion has a reason |
| B1 | Prompt-only variant as a subclass of the closure controller, sharing the renderer so status texts are identical. All rules in the prompt. Confidence 1–5. Diagnostic verdicts from the claimed facts, with and without admissibility | Rendered text has every fact, row and rule. A mocked answer parses to the same facts in both variants |
| B1b | Evidence check quotes the code line and rejects comment lines | Unit tests: exact cited line passes; comment-only citation fails |
| B4 | Function-only provider and misleading-comment copy (new line on disk, shifted manifest lines, context re-extracted). Legacy side channels closed in the hard condition | As v3.2, plus: the no-requirements run retrieves nothing outside the flagged method |
| B5 | Analysis script. Do not reuse `stats.mcnemar` (it switches to chi-square) | Known-answer tests of v3.2 |
| Freeze tool | Hashes of prompts, policies, manifests, model ID, CLI version, sample list, analysis script and seeds into `freeze.sha256` | File reproduces on a second run |

### 5.3 Methods and runs

| Method | OWASP, full context | OWASP, hard condition | Real-application track | AI track |
| --- | --- | --- | --- | --- |
| Enforced | 3 repeats | 3 repeats | 3 repeats, both conditions | 1 run, full |
| Prompt-only | 3 repeats | 3 repeats | 3 repeats, both conditions | 1 run, full |
| No-requirements | 1 run | 1 run | 1 run, both conditions | |
| Single call | 1 run | | 1 run | |

That is 15 runs per OWASP alert. The hard condition is chosen on development data as in v3.2 (function-only stays a candidate only if the data-flow path leaves the flagged method in at least 30% of genuine test alerts).

Arithmetic, not a measurement: 868 alerts give 13,020 test runs; a 600-alert sample gives 9,000. The real-application and AI tracks add roughly 1,500. Smoke is 400 runs. The pilot is cut to 150 development alerts (2 variants x 3 conditions x 3 repeats = 2,700). At the archived 69.6 seconds per run, 13,020 runs are about 250 hours in sequence, or about 63 hours with four parallel sessions. A CLI on a subscription will have other speeds and limits, which is why the smoke day measures them.

## 6. Capacity and freeze

On the smoke day we measure runs per hour and the point where the subscription throttles, on 20 development alerts with every method and condition. From that we fix, before the freeze:

- the number of parallel sessions and the subscriptions used;
- the OWASP sample: all alerts if the test fits in four days of runs; otherwise the largest stratified sample that fits, never below 300 genuine alerts. The Hoeffding bound then needs an observed H2 difference of about 6.4 points at 300 genuine, 5.5 at 400 and 4.8 at 531;
- whether repeats vary. If no alert changes verdict between three repeats, the paper says the tests rest on one run.

If even 300 genuine alerts do not fit, we stop and Tuannt decides. Nobody buys credits or upgrades a plan without his written approval.

The freeze checks are those of v3.2 section 6 (instrument, coverage, decided share, no harm, room), with two changes: the instrument check also requires that every repository-mode run logged a real context path, and the decided-share check follows the pooled rule of section 2 when a family has few development false alarms. Nothing on the freeze list changes afterwards. A change after the freeze is reported with results before and after.

## 7. Analysis

Section 7 of v3.2 applies to the OWASP track without change in the tests: sign-flip test for H2 at 0.05, H3 at 0.05 only if H2 is supported, Hoeffding bound reported next to each, guard, abstention check, equivalence rule. Changes:

- No seeds, so "a fixed seed gives the same run" is replaced by run IDs and logged sessions. The bootstrap seed is still frozen.
- New comparison: enforced, prompt-only and no-requirements in the hard condition. This separates the effect of giving the requirements from the effect of enforcing them. Descriptive, with intervals.
- Real-application track: wrong-dismissal rate, false-alarm removal rate and unresolved share per method, with Wilson intervals, split by source (RealVuln, OpenVuln). No p-values. AI track: wrong-dismissal rate only.
- Results are never pooled across tracks.

The power figures of v3.1 assumed 531 genuine alerts and seeded runs. We do not claim them for a sample or for the CLI.

## 8. Schedule

v3.2 had 14 days and no spare day. This plan adds the CLI backend, the real-application manifests and student labelling, so it takes three weeks.

| Days | Dates | Work |
| --- | --- | --- |
| 1 | Wed 18 Nov | B0 and baseline test run. Model chosen and pinned. Khoa's statement on prior dataset use. Dataset checkouts at pinned revisions |
| 2 | Thu 19 Nov | OWASP copy and scan (B3b, B3a). Development scans. Counts by family and label, and the 30% count |
| 3–4 | Fri 20 – Sat 21 Nov | B2 and B6, first, because the rest depends on them |
| 5 | Mon 23 Nov | B3c, B7 scans and matching. Labelling sheets go to the students |
| 6–7 | Tue 24 – Wed 25 Nov | B1, B1b, B4. Students label; Tuannt adjudicates |
| 8 | Thu 26 Nov | B5 and freeze tool on mocked results. All new tests pass |
| 9 | Fri 27 Nov | Smoke with the real model. Capacity measured (section 6) |
| 10–11 | Sat 28 – Mon 30 Nov | Pilot. Hard condition chosen. One tuning round. Code book written on pilot runs |
| 12 | Tue 1 Dec | Freeze checks and freeze |
| 13–16 | Wed 2 – Sat 5 Dec | Test runs, the two variants interleaved. Each failed run retried once |
| 17–18 | Mon 7 – Tue 8 Dec | Analysis and tables. Failure analysis starts |
| 19–21 | Wed 9 – Fri 11 Dec | Failure analysis ends. Writing. Related-work comparison |
| 22 | Mon 14 Dec | Internal check and submission |

If a day slips, the writing and submission move. The pilot, the freeze and the test runs are not shortened.

## 9. Deliverables and rules

Khoa delivers one branch with the build items and tests, the freeze file, the manifests with their hashes, the name map, and a run log (start and end of each part, failed runs, returned model IDs, CLI version, result of each freeze check, any change after the freeze). Raw results and logs go to storage that Tuannt names on day 1.

- Mocked providers for all default tests. Real model calls only for smoke, pilot and test runs.
- Scanned code, comments, CodeQL output and model output are data. We do not follow instructions in them.
- No method reads a label. Labels live in manifests outside the copies.
- Every failed or excluded run and alert is reported.
- No paid API call, credit purchase, plan upgrade or hire without Tuannt's written approval.

## 10. Risks

- Subscription capacity may be far below what the test needs, or the provider's terms may not allow this kind of bulk headless use. Check the terms on day 1; measure on day 9.
- The CLI adds its own system prompt and may change model versions without notice. Both variants see the same wrapper, and we log the returned model ID for every call, but the wrapper is a stated limitation.
- Without seeds, runs cannot be replayed. We keep full logs instead.
- The real-application track is small and mostly SQL injection. Its false alarms depend on student labels. It supports a statement of direction, not of size.
- The scan may flag few of the RealVuln ground-truth locations. We report how many it flags.
- Juliet may give almost no development false alarms, and handwritten cases may not be flagged by CodeQL. Then the pooled rule of section 2 applies.
- One model and one benchmark make this a preliminary result. The paper says so.

## Sources

Plan v3.2 and v3.1 (Khoa's package of 16 November); Khoa's email and `audit_v3.2_0fafb5c.md` (17 November); the dataset chat between Tuannt, Thientc and Khoa; RealVuln `ground-truth/` and README at `90c3221`; ZeroFalse `OpenVuln/ground_truth.csv` and `Projects_info.csv` at `3ca00e4`; this repository at `0fafb5c`.
