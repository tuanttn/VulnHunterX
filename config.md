# VulnHunterX – Config thí nghiệm v3.3 (theo ngày)

> Nguồn: [VulnHunterX_Experiment_Plan_v3.3.md](docs/paper/VulnHunterX_Experiment_Plan_v3.3.md) (gọi tắt **v3.3**) và [plan.md](plan.md). Khi khác nhau, **theo v3.3**.
> Vị trí code ghi theo commit `0fafb5c` (= `fdaec4a` cho `src/`, `benchmarks/`). Khi một build item đổi code, cập nhật dòng tương ứng ở đây **trong cùng PR**.
> Cổng kiểm tra trước mỗi build item và mỗi lần chạy: mục 5 (CLAUDE.md bắt buộc chạy cổng này).

**Ký hiệu trạng thái**

| Ký hiệu | Nghĩa |
| --- | --- |
| ✅ | Đã chốt trong v3.3 hoặc đã đo/ghi ở run log |
| ⏳ | Chờ Tuannt quyết (không tự chọn giá trị) |
| 🔧 | Code hiện tại **khác** config yêu cầu; build item ghi bên cạnh sẽ sửa |
| 📏 | Chốt bằng số đo (smoke ngày 9, pilot ngày 10–11) **trước freeze** |
| 💡 | Đề xuất của Khoa, không có trong v3.3 |
| 🧪 | Đã code + test (mock) trong working tree, **chưa merge**; đổi thành ✅ khi PR của item merge |

---

## 1. Config cố định toàn thí nghiệm

### 1.1 Phạm vi và dữ liệu
| Mục | Giá trị | Nguồn | TT |
| --- | --- | --- | --- |
| Ngôn ngữ / scanner | Java, chỉ CodeQL | v3.3 §1 #4 | ✅ |
| Họ lỗi | SQLi CWE-89, command injection CWE-78, path traversal CWE-22 (Juliet dev thêm CWE-23, CWE-36) | v3.3 §1 #4, §3.4 | ✅ |
| Track | OWASP (chính, H2/H3) · ứng dụng thực (RealVuln `human_authored` trừ WebGoat/VulnerableApp + OpenVuln CWE-22) · AI (RealVuln `llm_generated`). **Không gộp kết quả giữa track** | v3.3 §1, §3, §7 | ✅ |
| Dev | WebGoat `38096af`, VulnerableApp `6f5aded`, mẫu Juliet Java 1.3, case false alarm viết tay. Không bao giờ báo cáo làm kết quả | v3.3 §3.4 | ✅ |
| OWASP BenchmarkJava commit | `a452b3aafd232245d0753e54eb243d6651f8ef96` | plan.md §9 #5 (v3.3 không ghi commit) | ⏳💡 |
| RealVuln / ZeroFalse | `90c3221` / `3ca00e4`; repo đích ở `commit_sha` / `buggy_commit_id` | v3.3 §3.2 | ✅ |
| CWE-77 trong `llm_generated` | 3 entry; tính vào command injection theo `config/cwe-families.json` của RealVuln thì mới ra 128. Manifest giữ CWE nguồn + ghi mapping | run log ngày 1; v3.3 §3.2 "keep the source CWE" | ✅ (mapping ghi ở manifest) |

### 1.2 Toolchain (đã pin ngày 1)
| Mục | Giá trị | TT |
| --- | --- | --- |
| Python | 3.12.10, `.venv`, `pip install -e ".[dev,benchmark]"` | ✅ |
| CodeQL CLI | 2.27.4; `codeql/java-queries` 1.12.0, `codeql/java-all` 9.3.4 | ✅ |
| JDK | Temurin 21.0.13+9 (SHA-256 trong run log) | ✅ |
| litellm (client version) | 1.109.1 — **thuộc danh sách freeze** (v3.3 §5.2). 💡 Không nâng cấp từ ngày 1 để smoke, pilot và test cùng version | ✅ |
| Môi trường | `PYTHONUTF8=1`; kích hoạt `. ..\exp-data\scripts\env.ps1`; pytest `--basetemp` ngắn (`D:\t\<tên>`) | ✅ |

### 1.3 Scan CodeQL và manifest
| Mục | Giá trị | Nguồn | TT |
| --- | --- | --- | --- |
| Tạo DB | `codeql database create <db> --language=java --build-mode=none --source-root <copy>` (gọi CLI trực tiếp; `codeql/database.py` chỉ bật build mode none cho C#) | plan.md §3.5, audit | ✅ |
| Phân tích | `codeql database analyze <db> codeql/java-queries:codeql-suites/java-security-extended.qls --format=sarif-latest --output <file>.sarif` | v3.3 §3.2 "same CodeQL version and suite" | ✅ |
| Lọc họ | theo CWE tag, chuẩn hóa `CWE-89` (dùng `sarif/parser.py:_normalize_cwe`), giữ tag gốc (dạng `external/cwe/cwe-078`) | v3.3 §5.2 B2 | ✅ |
| Rule loại | `java/exec-tainted-environment`, `java/relative-path-command`: không vào manifest, **có đếm** | v3.3 §5.2 B2 | ✅ |
| Chọn alert | 1 alert / test case, đúng họ của nhãn, ưu tiên rule có data-flow path, ghi rule được chọn | v3.3 §5.2 B3 | ✅ |
| Định dạng | JSONL + `.sha256`, path dùng `/`, không đăng ký redaction rule | v3.3 §5.2 B3; plan.md §6 | ✅ |
| Khớp ground truth (RealVuln) | cùng file, dòng chồng lấn, cùng họ → thật; còn lại 2 sinh viên gán nhãn độc lập, Tuannt phân xử | v3.3 §3.2 | ✅ |
| Context | tree-sitter CSV cho **mọi** bản copy: đặt SARIF vào `output/java/<copy>/` rồi `vuln-hunter-x prepare --local-path repos/java/<copy> --name <copy> --lang java --skip-db --backend treesitter`; kiểm tra `functions.csv`, `callers.csv`, `classes.csv` tồn tại | v3.3 §5.2 B7; run log ngày 1 | ✅ |

### 1.4 Method → cách chạy
| Method | Approach | Option bắt buộc | TT |
| --- | --- | --- | --- |
| Enforced | `vulnhunterx-repo` | `route=auto` | ✅ |
| Prompt-only | `vulnhunterx-repo` | `route=prompt_only` (**chưa có**: `repo_context.py:102` chỉ nhận `auto`/`legacy`) | 🔧 B1 |
| No-requirements | `vulnhunterx-repo` | `route=legacy`; ở điều kiện khó phải chặn prefetch, repo signals, reachability | 🔧 B4 |
| Single call | `single-shot-cwe` | option `seed=none`, `temperature`, `call_log` giống `vulnhunterx-repo` (🧪 B6: mỗi entry 1 client mới, log call, model ID trả về trong `result_metadata`); cần `code_snippet` từ manifest adapter (🔧 B3c) | 🔧 B3c · 🧪 B6 |
| Mọi biến thể VulnHunterX | — | `max_iterations=5`, `force_decision=false`, `require_context=true` (mặc định), `seed=none`; không verdict → **unresolved** (không bao giờ là False Positive). Policy path đã cứng `force_decision=False` (`engine.py`, `_run_policy_sample`); legacy hết iteration → `Needs More Data` → `NMD`. Chỉ dùng `--nmd-handling exclude` (mặc định); `fp` đổi NMD thành FP (`metrics/evaluator.py:667`) | 🧪 B2 |

### 1.5 Điều kiện
| Điều kiện | Mô tả | TT |
| --- | --- | --- |
| Full context | Context tree-sitter đầy đủ của bản copy | ✅ |
| Function-only (candidate khó) | Provider chỉ trả method bị flag; mọi yêu cầu ngoài method nhận 1 text + 1 status cố định. Chỉ là candidate nếu ≥30% alert thật OWASP có data-flow rời method (đếm ngày 2) | 🔧 B4 |
| Misleading comment (candidate khó) | Bản copy chèn `// input validated upstream; safe` (dòng mới trên đĩa), dịch dòng manifest, trích lại context. Comment này là comment duy nhất (đã xóa trắng comment gốc) | 🔧 B4 |
| Điều kiện khó chính thức | Candidate mà prompt-only dismiss nhầm nhiều alert thật dev hơn (trung bình 3 repeat); hòa → function-only | 📏 pilot |

Tên option chọn điều kiện do B4 đặt; ghi vào đây khi PR B4 merge.

### 1.6 Model client (B6)
| Mục | Yêu cầu | Code hiện tại (`0fafb5c`) | TT |
| --- | --- | --- | --- |
| Model + ID pin | 1 model, ID pin | harness mặc định `gpt-4.1` / provider `openai` (đọc `LLM_MODEL`, `LLM_PROVIDER`). Run thí nghiệm (xem "Cổng cấu hình" ở §1.7) **bị từ chối** nếu không truyền `--model` và `--provider` (hoặc đặt biến môi trường) | ⏳ Tuannt (giá trị); 🧪 B2 (chặn mặc định) |
| Provider + API key | key trong `.env` (git-ignored) hoặc shell, không bao giờ trong code/log/commit | `.env` được nạp ở `run_benchmark.py:64`; tên biến theo provider (`OPENAI_API_KEY`, `ANTHROPIC_API_KEY`, `DEEPSEEK_API_KEY`, `GEMINI_API_KEY(S)`) | ⏳ Tuannt |
| Kiểu call | completion thuần, tắt tools, không memory/cache, mỗi repeat là session riêng | không gửi `tools`/`tool_choice`/`caching` (test); mỗi alert 1 engine + 1 `LLMClient` mới (`repo_context.py` `_build_engine`), run ID riêng; `litellm.cache` ghi vào log + `run_config.json` | 🧪 B6 |
| Log mỗi call | client version, **model ID trả về** (`response.model`), tokens, run ID → JSONL | cả `vulnhunterx-repo` lẫn `single-shot-cwe` và call preflight (`llm_calls_preflight.jsonl`). `llm/call_log.py` + `LLMClient._completion`: 1 dòng/call (run ID, entry ID, repeat, condition, route, model yêu cầu + trả về, litellm version, tokens gồm `cached_input_tokens`, latency, finish_reason, tham số đã gửi). Không ghi prompt/response; lỗi chỉ ghi loại + status. Harness tự đặt `<run_dir>/llm_calls_<dataset>_<tên run>.jsonl` (trừ dry-run); `models_returned` vào result metadata. Một dòng = một lần `litellm.completion` của client; retry nội bộ của litellm (`num_retries`) không thấy được. Harness từ chối chạy thật nếu `litellm.cache` bật | 🧪 B6 |
| Seed | **không dựa vào seed** | option `seed=none` của `vulnhunterx-repo` → không gửi seed. Mặc định client/CLI vẫn 42 (`core/constants.py:25`, giữ cho người dùng khác) → lệnh thí nghiệm (có `--repeats`/`--condition`, không `--dry-run`) **bị harness từ chối (exit 2)** nếu không truyền `--approach-option seed=none`; seed số cố định chỉ được phép kèm cảnh báo | 🧪 B6 |
| Temperature | v3.3: không giả định được hỗ trợ. Giá trị cụ thể **chưa chốt** | B6 thêm option `temperature` nhận `default` / `none` / một số (`none` = không gửi, service tự chọn); mặc định vẫn 0.0 (`constants.py:22`). `litellm.drop_params=True` (`client.py:36`) có thể âm thầm bỏ tham số: log ghi tham số **đã gửi** (`params_sent`) và tham số đã gửi nhưng không có trong danh sách hỗ trợ của litellm cho model đó (`params_outside_litellm_supported_list`; `null` = litellm không biết model). Danh sách là bảng tĩnh của litellm: bằng chứng nên có drop, không phải bằng chứng provider đã nhận gì | ⏳ Tuannt (plan.md §9 #4) – không chặn code hay merge (B6 chỉ thêm tham số); chặn **chạy model thật** (harness từ chối run thí nghiệm không nêu temperature) và freeze |
| Tham số khác | ghi vào run log | `max_tokens` 4096, retry khi cắt cụt 8192 (`constants.py:32,36`), `request_timeout` 180 s | 💡 ghi run log; đưa vào freeze nếu Tuannt đồng ý |
| Prompt cache phía provider | v3.3 yêu cầu "no cache" | client đã đọc `cached_tokens` (`client.py:79-103`); một số provider tự cache prefix, không tắt được từ client | 💡 B6 log `cached_tokens` mỗi call; báo Tuannt nếu khác 0 |
| Test mặc định | mock provider | — | ✅ |

### 1.7 Chạy harness (`benchmarks/scripts/run_benchmark.py`)
| Flag | Giá trị thí nghiệm | Mặc định code | TT |
| --- | --- | --- | --- |
| `--approach-option max_iterations=5` | 5 cho mọi biến thể | harness luôn `setdefault` 10 từ `benchmark.yaml` nếu không truyền option (approach default 3 không bao giờ dùng tới) → **bắt buộc truyền ở mỗi lệnh** (run thí nghiệm thiếu option bị từ chối; giá trị khác 5 chỉ cảnh báo); test xác nhận 5 tới `Config` | 🧪 B2 |
| `--approach-option force_decision=false` **và** `--no-force-decision` | tắt forced choice | mặc định vẫn bật; truyền cả hai thì `Config.verification.force_decision=False` (test); `run_config.json` ghi `approach_options` và `force_decision`. Run thí nghiệm thiếu một trong hai, hoặc để bật, bị từ chối | 🧪 B2 |
| **Cổng cấu hình của harness** | run có `--repeats`/`--condition` và **không** `--dry-run` phải nêu rõ: `--model`, `--provider`, `seed=none`, `max_iterations`, `force_decision=false` + `--no-force-decision`, `--nmd-handling exclude`, `require_context` không `false`, `temperature` được nêu rõ (`none` hoặc một số; giá trị do Tuannt quyết, harness chỉ đòi phải nêu). Thiếu hoặc sai → `exit 2` kèm danh sách mọi lỗi cùng lúc, trước khi tạo approach hay gọi model | `run_benchmark.py` `_experiment_config_problems`. Run không có hai flag lặp và dry-run không bị chặn (người dùng khác giữ hành vi cũ). Chưa chặn: `route` (B1/B4 sẽ có giá trị hợp lệ) | 🧪 B2 |
| `--repeats N`, `--condition <nhãn>` | 3 (enforced, prompt-only), 1 (no-req, single call); repeat + condition trong tên run/file | checkpoint `<dataset>_<approach>[_<route>]_<condition>_r<k>_results.json` (condition mặc định `full`); mỗi repeat 1 approach mới; result metadata + `findings.jsonl` có `run_id` (1/alert/repeat), `repeat`, `condition`; `--resume` theo từng repeat; không dùng chung với `--iteration-sweep`. Không truyền hai flag → tên cũ | 🧪 B2 |
| Kiểm tra offline (không gọi model) | `python -m scripts.exp.b2_manifest_routing <manifest.jsonl> --expect <family>=<n> ...` (mọi alert ra đúng 1 policy, không có rule bị loại); `python -m scripts.exp.b2_route_impact [entries.json ...]` (dataset nào đổi route do B2) | 🧪 B2 |
| `require_context` (approach option) | `true`: thiếu `functions/callers/classes.csv` → ERROR, không fallback snippet; ghi `context_path` vào metadata | mặc định `true` ở `vulnhunterx-repo`; engine có `verification.require_repo_context` (mặc định `false` cho CLI) chặn cả hai chỗ fallback | 🧪 B2 |
| `--run-dir` | thư mục ở nơi lưu ngoài git | `benchmarks/results/<timestamp>` | ⏳ nơi lưu (Tuannt); tạm `../exp-data/runs/` |
| `--anchor none` | manifest đã có sink line, không anchor lại bằng OpenGrep | `auto` | 💡 xác nhận ở B3c |
| `--no-redact` | không redaction trong bộ nhớ (copy đã xử lý trên đĩa) | redaction bật cho dataset có rule | 💡 không có tác dụng nếu manifest không đăng ký rule; giữ để chắc chắn |
| `-j`, `--llm-concurrency` | số session song song | 4 / 4 | 📏 smoke ngày 9 |
| `--dry-run` | mọi lần chạy **không** phải smoke/pilot/test | tắt | ✅ |
| `--skip-preflight` | dùng với `--dry-run`. Preflight là 1 call thật | tắt | ✅ |
| `--resume`, `--only-entries` | retry run lỗi **1 lần như run mới** (ghi vào run log) | — | ✅ |

**Mẫu lệnh** (sau khi B2/B1/B4/B3c merge; `<...>` thay theo bảng trên, tên dataset là tên adapter B3c đặt):

```powershell
python benchmarks/scripts/run_benchmark.py `
  --dataset <manifest-adapter> <option chọn file manifest, do B3c đặt> `
  --approach vulnhunterx-repo `
  --provider <provider> --model <model-id-pin> `
  --approach-option route=<auto|prompt_only|legacy> `
  --approach-option max_iterations=5 `
  --approach-option force_decision=false --no-force-decision `
  --approach-option seed=none --approach-option temperature=<⏳ Tuannt> `
  <option điều kiện của B4> --repeats <3|1> --condition <full|...> `
  --anchor none --no-redact `
  -j <N> --llm-concurrency <N> `
  --run-dir <nơi lưu>/<track>_<method>_<condition>
```
Tên file do B2 đặt (🧪): trong `--run-dir`, checkpoint `<dataset>_vulnhunterx-repo_<route>_<condition>_r<k>_results.json` và call log `llm_calls_<dataset>_vulnhunterx-repo_<route>_<condition>_r<k>.jsonl`. 💡 Thư mục run: `<nơi lưu>/<track>_<method>_<condition>` như trên.

### 1.8 Lưu trữ, freeze, phân tích
| Mục | Giá trị | TT |
| --- | --- | --- |
| Kết quả thô + log JSONL | ngoài git, ở nơi Tuannt chỉ định; commit chỉ hash | ⏳ nơi lưu |
| Danh sách freeze (`freeze.sha256`) | v3.3 §5.2: prompts, policies, manifests, model ID, client version, danh sách mẫu, analysis script, seeds. plan.md §5.2 (theo v3.2) thêm: questions, điều kiện khó, code book, bootstrap seed. Temperature và tham số gửi đi chỉ thêm nếu chốt cố định | ✅ (temperature ⏳) |
| Phân tích OWASP | v3.3 §7: sign-flip H2 0.05; H3 0.05 chỉ khi H2 support; Hoeffding cạnh mỗi kết quả; guard; abstention check; equivalence rule; bootstrap seed freeze. Chi tiết từ v3.2 §7 (plan.md §5.3): sign-flip 2 phía, bootstrap 10,000, equivalence = 95% CI trong ±3 điểm. **Không** dùng `stats.mcnemar` | ✅ |
| So sánh mô tả | enforced vs prompt-only vs no-requirements ở điều kiện khó, có khoảng tin cậy | ✅ |
| Track phụ | Wilson CI 95%, không p-value; wrong-dismissal, false-alarm removal, unresolved share theo method, tách RealVuln / OpenVuln; AI chỉ wrong-dismissal | ✅ |

---

## 2. Bảng chạy LLM (chỉ 3 phase được gọi model thật)

| Phase | Ngày | Dữ liệu | Method × điều kiện × lặp | Tổng run | Chốt sau phase |
| --- | --- | --- | --- | --- | --- |
| Smoke | 9 (27/11) | 20 alert **dev** | mọi method, mọi điều kiện | 400 (v3.3 §5.3) | session song song, cỡ mẫu OWASP, repeat có biến thiên không |
| Pilot | 10–11 (28–30/11) | 150 alert **dev** | enforced + prompt-only × 3 điều kiện × 3 repeat (v3.3 §5.3; 3 điều kiện = full + function-only + misleading comment, theo v3.2) | 2,700 | điều kiện khó; ≤1 vòng tuning; code book |
| Test OWASP | 13–16 (2–5/12) | toàn bộ alert hoặc mẫu (≥300 alert thật) | enforced 3+3, prompt-only 3+3, no-req 1+1, single call 1 (full) | 15 / alert (868 → 13,020; 600 → 9,000) | – |
| Test ứng dụng thực | 13–16 | RealVuln human (trừ WebGoat, VulnerableApp) + OpenVuln CWE-22 | enforced, prompt-only: 3 repeat × 2 điều kiện; no-req 1 × 2 điều kiện; single call 1 | ≈1,500 cùng track AI | – |
| Test AI | 13–16 | RealVuln `llm_generated`, alert khớp ground truth | enforced, prompt-only: 1 run, full | (trong ≈1,500) | – |

Ngoài 3 phase này: `--dry-run` và mock. Mỗi lần gọi thật chỉ chạy khi Khoa yêu cầu trong phiên làm việc.

---

## 3. Config theo ngày

### Ngày 1 – 18/11 – P0 Môi trường
- [x] Toolchain mục 1.2 cài và ghi run log.
- [x] Dataset ở revision pin (mục 1.1); OWASP commit ⏳.
- [ ] ⏳ Model + ID pin, provider, API key (đặt trong `.env`, không commit).
- [ ] ⏳ Nơi lưu kết quả thô.
- [ ] ⏳ Temperature (cần trước ngày 3).

### Ngày 2 – 19/11 – P1 Dữ liệu (không gọi model)
- Scan theo mục 1.3, cùng CLI 2.27.4 + `java-security-extended` cho OWASP, Juliet, WebGoat, VulnerableApp.
- OWASP copy: chỉ `src/main/java`, bỏ `report/`; đổi `BenchmarkTest…`, `org.owasp.benchmark.{helpers,testcode,service}`, `benchmarkprops`, `@WebServlet` path, `"Problem executing cmdi - TestCase"`; **giữ `org.owasp.esapi`**; xóa trắng comment, giữ số dòng; name map ngoài copy.
- Juliet dev: redact **trên đĩa** (xóa trắng comment, đổi tên `bad`/`good*`, class/file chứa CWE, tên biến thể; nhất quán toàn repo), label map theo line range mọi method `bad*`/`good*`, luật tên file cho `_81`, thêm CWE-23/36, copy `testcasesupport/`.
- Kiểm tra trước khi qua ngày 3: có alert taint-flow với `codeFlows`; tỷ lệ alert thật OWASP có data-flow rời method (ngưỡng 30%); số alert theo họ × nhãn (so với 868/531/337); dev theo nguồn × họ × nhãn.

### Ngày 3–4 – 20–21/11 – P2 Core (B2, B6; mock)
> Trạng thái: code + test mock xong, commit `dea728f` trên branch `exp/day3-4-core` (B2 + B6 gộp một PR, đã push, chưa mở PR). Temperature chưa chốt: không chặn merge (B6 chỉ thêm tham số), chặn chạy model thật (harness từ chối run không nêu temperature). Chi tiết: `docs/paper/run_log.md` (Day 3–4).
- B2: `entry_to_finding` (`benchmarks/approaches/base.py:154-166`) truyền `cwe_ids` chuẩn hóa + tag gốc, message, data-flow path; thiếu context → ERROR (`engine.py:1865-1871`, `context/provider.py:365-368`), log context path; `max_iterations=5`, `force_decision=false`; `--repeats` + tên run; metadata `decision_source`, facts, end reason, confidence.
- B6: bỏ seed; temperature theo quyết định của Tuannt; log JSONL mỗi call (client version, model ID trả về, tokens, run ID, `cached_tokens`); tắt tools; mỗi repeat là client/session mới.
- Sau khi merge: cập nhật cột "Code hiện tại" ở mục 1.6, 1.7.

### Ngày 5 – 23/11 – P3 Manifest (B3c, B7; mock)
> Trạng thái: code + dữ liệu xong, commits `7084c09` + `696b89b` trên branch cục bộ `exp/day5-manifests` (xếp chồng lên `exp/day3-4-core` và `exp/day2-data-prep`, **chưa push**). Cổng bước 3 (item phụ thuộc đã merge) được **bỏ qua có chủ đích** theo yêu cầu của Khoa; phải `rebase --onto` khi các PR nền merge. Chi tiết: `docs/paper/run_log.md` (Day 5).
> Config đã dùng: adapter `alert-manifest` (`--dataset-option manifest=<jsonl>`, `repos_dir`, `snippet_window` 💡 mặc định 40, `strict_hash`); copy tên trung tính `app-NN`/`gen-NN`/`oss-NN` (map ngoài repo); quét CodeQL 2.27.4 `java-security-extended` `--build-mode=none` trên bản copy **đã xóa build file** (kể cả hai bản copy dev WebGoat/VulnerableApp, quét lại ngày 5), 2 job, RAM 3 GB (repo lớn 6–8 GB, một lần một repo).
- Adapter manifest: 1 `GroundTruthEntry`/alert, `sink_line`, `rule_id`, CWE, message, data-flow path, `metadata.repo_name`, `code_snippet`; nhãn chỉ đọc từ manifest; không redaction rule.
- Xác nhận `--anchor none` / `--no-redact` không đổi số entry (số entry = số dòng manifest).
- B7: scan repo track phụ theo mục 1.3; context cho mọi copy.
- Sheet gán nhãn: alert không khớp ground truth trong 3 họ; 2 sinh viên gán **độc lập**, từ code, **không xem output model**; Tuannt phân xử; alert không quyết được → loại và đếm.

### Ngày 6–7 – 24–25/11 – P4 Biến thể (B1, B1b, B4; mock)
- `route=prompt_only` có trong `repo_context.py` (nhận giá trị mới); render chung với enforced; prompt có mọi fact, bảng verdict, luật admissibility (kể cả "comment không phải bằng chứng"), confidence 1–5.
- B1b: citation phải trích đúng dòng code trong slice, không phải comment; cùng luật ghi vào prompt-only.
- B4: option điều kiện (ghi tên vào mục 1.5); no-requirements ở điều kiện khó không retrieve gì ngoài method bị flag.

### Ngày 8 – 26/11 – P5 B5 + freeze tool (mock)
- Bootstrap seed: chọn 1 số, ghi vào config analysis, đưa vào freeze.
- Freeze tool hash đủ danh sách mục 1.8; chạy 2 lần ra cùng file.
- Toàn bộ test mới pass.

### Ngày 9 – 27/11 – P6 Smoke (**LLM thật**)
Trước khi chạy:
- [ ] Model ID pin, key, temperature đã chốt (không còn ⏳ ở mục 1.6).
- [ ] Không còn 🔧 hoặc 🧪 cho B1, B2, B3c, B4, B6 (🧪 = chưa merge).
- [ ] `--run-dir` trỏ tới nơi lưu ngoài git.
- [ ] Chạy thử 1 alert với `--dry-run --skip-preflight` cho từng method × điều kiện.
Ghi sau khi chạy: run/giờ, điểm throttle, số session (`-j`, `--llm-concurrency`), repeat có biến thiên không (không alert nào đổi verdict qua 3 repeat → paper nói kiểm định dựa trên 1 run), model ID trả về, `decision_source` mọi run enforced, context path thật ở mọi run.

Chốt cỡ mẫu OWASP (v3.3 §6): **toàn bộ alert** nếu test chạy xong trong **4 ngày**; nếu không, mẫu phân tầng lớn nhất vừa 4 ngày, **không dưới 300 alert thật**. Nếu 300 alert thật cũng không vừa → **dừng, Tuannt quyết**.

### Ngày 10–11 – 28–30/11 – P7 Pilot (**LLM thật**)
- 150 alert dev, xen kẽ 2 biến thể. Không dùng alert OWASP.
- Tuning tối đa 1 vòng: chỉ đổi guidance chung cho **cả hai** biến thể, chạy lại alert bị ảnh hưởng; ghi run log.
- Chốt điều kiện khó (mục 1.5).
- Chuyển log pilot cho Tuannt viết code book failure analysis (v3.3 §8 ngày 10–11).

### Ngày 12 – 1/12 – P8 Freeze
- 5 freeze check (plan.md §5.2), với 2 thay đổi của v3.3 §6: instrument check đòi **mọi run repository mode ghi context path thật**; decided share dùng luật **gộp 3 họ** khi một họ ít false alarm dev. Rút mẫu OWASP với seed cố định, phân tầng họ × nhãn, ≥300 alert thật.
- Ghi `freeze.sha256`. Từ đây **không đổi** bất cứ mục nào ở danh sách freeze; thay đổi bắt buộc → PR `[POST-FREEZE]`, Tuannt duyệt trước, báo kết quả trước/sau.

### Ngày 13–16 – 2–5/12 – P9 Test runs (**LLM thật**)
- Config = đúng bản freeze. Trước mỗi đợt chạy: `freeze.sha256` kiểm lại khớp (hash lại và so).
- Xen kẽ thời gian chạy 2 biến thể. Run lỗi retry 1 lần như run mới. Theo dõi model ID trả về có đổi không.

### Ngày 17–18 – 7–8/12 – P10 Phân tích (không gọi model)
- Analysis script đã freeze, bootstrap seed đã freeze. Bảng theo từng track, không gộp.

---

## 4. Việc cần Tuannt chốt trước khi config hoàn chỉnh

| # | Mục | Hạn | Chặn |
| --- | --- | --- | --- |
| 1 | Model + ID pin, provider, API key | ngày 1 | B6 test thật, smoke |
| 2 | Nơi lưu kết quả thô | ngày 1 | `--run-dir` từ ngày 9 |
| 3 | Temperature (mặc định service / giá trị cố định; có vào freeze không) | trước ngày 3 | B6 |
| 4 | OWASP commit `a452b3a` | ngày 1 | B3b (ngày 2) |
| 5 | 💡 `max_tokens`, `request_timeout` có vào danh sách freeze không | trước ngày 8 | freeze tool |

---

## 5. Cổng kiểm tra config (trước mỗi build item và mỗi lần chạy)

1. **Đúng ngày, đúng phase:** mở mục 3 của ngày hiện tại; việc định làm phải nằm trong đó.
2. **Không còn ⏳ chặn:** mọi mục ⏳ mà việc này phụ thuộc (mục 4, cột "Chặn") đã có quyết định. Chưa có → dừng, hỏi Khoa/Tuannt; không tự chọn giá trị.
3. **Item phụ thuộc đã merge:** theo bảng branch plan.md §10.1. Dòng 🔧 của item trước đã được cập nhật trong config.md.
4. **Đối chiếu code với mục 1:** grep/đọc các vị trí code ghi trong mục 1.6, 1.7 cho các giá trị việc này dùng (iterations, force decision, route, seed/temperature, context fallback). Lệch → sửa trong build item hoặc dừng và báo.
5. **Gọi model thật?** Chỉ ở ngày 9, 10–11, 13–16 và khi Khoa yêu cầu trong phiên. Còn lại `--dry-run --skip-preflight` và mock.
6. **Sau freeze:** việc có chạm mục trong danh sách freeze (mục 1.8) không? Có → dừng, báo trước.
7. **Ghi lại:** kết quả cổng (đạt / lệch gì) vào mô tả PR (mục "Chạm vào mục freeze") hoặc run log trước khi chạy.
