---
title: DevSecOps Dependency Resolver
colorFrom: green
colorTo: blue
sdk: docker
pinned: false
app_port: 8000
base_path: /web
tags:
  - openenv
  - devsecops
  - python
  - rl-environment
---

# DevSecOps Dependency Resolver — OpenEnv Environment

## Overview

Software supply-chain incidents have become the dominant attack vector against modern infrastructure. **Log4Shell** (CVE-2021-44228, December 2021) made millions of Java systems remotely exploitable through a transitive logging dependency. The **Equifax breach** (2017) leaked 147 million records because of an unpatched Apache Struts dependency. The **xz-utils backdoor** (CVE-2024-3094, March 2024) showed that even single-maintainer transitive dependencies can be hijacked. Across all three incidents, the failure mode was the same: a vulnerable package buried somewhere in the dependency tree, no human watching closely enough, no fast deterministic way to validate a patch before shipping it.

Human DevSecOps engineers spend hours manually untangling version matrices, parsing pip resolver tracebacks, and testing CVE patches. Tools like Dependabot, Renovate, and Snyk can *detect* vulnerabilities but cannot *autonomously reason* about complex version constraint conflicts or trace multi-level transitive dependency chains. There is currently no benchmark in the OpenEnv ecosystem for training agents that close this gap.

**This environment is that benchmark.** An AI agent manages a Python `requirements.in` manifest and must resolve real dependency conflicts and patch real CVEs using a fast, offline, deterministic validation engine powered by **`uv`** (Astral's Rust-based package manager). Every step takes under 100 ms, every grade is reproducible, and the entire environment runs offline inside a 2-vCPU / 8 GB container.

### Who would use this environment

- **RL researchers** training agents for code-modifying tool use, where the reward signal needs to be dense, deterministic, and grounded in real subprocess output rather than synthetic metrics
- **Security tool builders** evaluating LLM agents as a next-generation Dependabot, where the agent must do more than flag vulnerabilities — it must propose and verify patches end-to-end
- **DevOps platform teams** benchmarking which frontier model is actually capable of autonomous dependency triage on real codebases
- **Curriculum designers** for agent training, since the easy → medium → hard task progression mirrors the real difficulty curve of supply-chain triage in production

### What the agent must demonstrate

- **Read and parse structured error output** (`uv pip compile` stderr — real, not synthetic)
- **Reason about version constraint mathematics** (transitive `<` and `>=` bounds intersecting)
- **Trace CVE vulnerability chains** through resolved dependencies, not just direct ones
- **Make targeted, minimal changes** without introducing regressions, and resist the temptation to take destructive shortcuts (the grader has anti-cheat that rejects deletion-based "solutions")

### Why this is more than a toy

Unlike most RL benchmarks that wrap a game or a simulated UI, this environment runs the **same `uv` resolver** that production Python projects use today. A patch that works here would work in a real CI pipeline. A model that scores 1.00 here can be put behind a real GitHub webhook tomorrow. There is no abstraction layer between the environment and the actual tool an engineer would invoke.

---

## Environment Architecture

| Component | Implementation |
|-----------|---------------|
| Dependency resolver | `uv pip compile` subprocess |
| CVE scanner | In-memory Python dictionary (PyPI Advisory Database subset) |
| Validation speed | < 100ms per `step()` |
| Network access | Disabled — fully offline and deterministic |
| Concurrency | Up to 4 simultaneous sessions |

### System Diagram

![System Architecture Diagram](assets/system_diagram.png)

The agent never touches `uv` or the CVE database directly — every interaction goes through the typed `DevSecOpsAction` / `DevSecOpsObservation` contract, and every reward comes from a real subprocess exit code, not a synthetic score.

---

## Observation Space

Each observation is a `DevSecOpsObservation` Pydantic model with the following fields:

| Field | Type | Description |
|-------|------|-------------|
| `manifest_content` | `str` | Current contents of the `requirements.in` file |
| `build_status` | `str` | `"SUCCESS"`, `"FAILED"`, or `"UNKNOWN"` |
| `build_stderr` | `str` | Full error trace from `uv pip compile` when build fails |
| `cve_report` | `list[dict]` | Active high-severity CVEs in the resolved dependency tree |
| `reward` | `float` | Shaped reward for this step |
| `done` | `bool` | Whether the episode has ended |

Each CVE entry in `cve_report` has the structure:
```json
{
  "id": "CVE-2023-37920",
  "severity": "HIGH",
  "desc": "Removal of e-Tugra root certificate",
  "fixed_in": "2023.7.22",
  "package": "certifi"
}
```

---

## Action Space

Each action is a `DevSecOpsAction` Pydantic model:

| `action_type` | Parameters | Description |
|--------------|------------|-------------|
| `update_package` | `package_name`, `new_version_specifier` | Modifies a package line in the manifest (e.g., `"==2.31.0"`) |
| `remove_package` | `package_name` | Removes a package entry from the manifest |
| `run_validation` | — | Triggers `uv pip compile` and CVE scan, returns updated observation |
| `submit_final_manifest` | — | Ends the episode and triggers the final grader |

Example action payloads:
```json
{"action_type": "update_package", "package_name": "requests", "new_version_specifier": "==2.31.0"}
{"action_type": "remove_package", "package_name": "urllib3"}
{"action_type": "run_validation"}
{"action_type": "submit_final_manifest"}
```

---

## Tasks

### Task 1 — The Dead Link (Easy)

**Initial manifest:**
```
requests==99.0.0
```

**Objective:** The manifest references a version that does not exist on PyPI. The agent must read the `build_stderr` not-found error and update `requests` to a valid stable version (e.g., `==2.31.0`).

**Grader:** Binary — `uv pip compile` exit code 0 gives `score = 1.0`, otherwise `0.0`.

**Constraint (anti-cheat):** `requests` must remain in the final manifest. An agent that simply deletes the broken package to make the manifest empty receives `score = 0.0`. The task is "fix the version", not "make the problem go away".

**Expected difficulty:** Easy. A single `update_package` action followed by `run_validation` and `submit_final_manifest` is sufficient.

---

### Task 2 — The Version Collision (Medium)

**Initial manifest:**
```
botocore==1.29.0
urllib3>=2.0
```

**Objective:** `botocore==1.29.0` has a strict transitive requirement of `urllib3<1.27`, which is mathematically incompatible with the directly-pinned `urllib3>=2.0`. The agent must parse the conflict trace in `build_stderr`, identify the removable *outer* constraint (`urllib3>=2.0`), and delete it so `botocore` can resolve its own compatible `urllib3` version.

**Grader:** Binary — clean build gives `score = 1.0`, otherwise `0.0`.

**Constraint (anti-cheat):** `botocore` must remain in the final manifest. The "shortcut" of deleting `botocore` (the package the task is about) instead of resolving the conflict around it is rejected with `score = 0.0`. The task is "make `botocore` work", not "remove `botocore`".

**Expected difficulty:** Medium. Requires reading and reasoning about a transitive conflict trace and choosing the correct constraint to remove.

---

### Task 3 — The Deep CVE Patch (Hard)

**Initial manifest:**
```
requests==2.28.1
certifi==2022.12.7
```

**Objective:** The manifest builds successfully but contains two known CVEs:
- `requests==2.28.1` has CVE-2023-32681 (Proxy-Authorization header leak), fixed in `2.31.0`
- `certifi==2022.12.7` has CVE-2023-37920 (e-Tugra root cert), fixed in `2023.7.22`

The agent must identify both vulnerable packages from `cve_report`, upgrade them to patched versions, and verify the build still succeeds.

**Grader:** Compound scoring:
- Build fails → `score = 0.0`
- Build succeeds but CVEs remain → `score = 0.5`
- Build succeeds and `cve_report` is empty → `score = 1.0`

**Constraint (anti-cheat):** Both `requests` and `certifi` must remain in the final manifest. A naive "delete the vulnerable packages" strategy would technically result in an empty manifest that builds with no CVEs (because there are no packages to be vulnerable) — this is rejected with `score = 0.0`. The task is "patch the CVEs", not "make the application stop using those libraries".

**Expected difficulty:** Hard. Requires reading CVE metadata, upgrading multiple packages without breaking the build, AND resisting the destructive shortcut.

---

## Reward Function

The environment provides dense, shaped rewards over the full trajectory — not just a binary end-of-episode signal. Partial progress is rewarded; clearly undesirable behavior such as infinite loops and wasted actions is penalized.

| Event | Reward |
|-------|--------|
| `run_validation` reduces error line count vs. previous step | `+0.2` |
| CVE removed from `cve_report` without breaking the build | `+0.2` per CVE |
| `submit_final_manifest` on a perfect state (build OK + no CVEs) | `+0.5` bonus |
| `run_validation` increases error line count (regression) | `−0.1` |
| Repeated identical action (loop penalty) | `−0.05` |
| `remove_package` on a package not in the manifest (wasted action) | `−0.05` |
| Invalid `update_package` or `remove_package` call (missing name or specifier) | `−0.05` |

Per-step rewards are clamped to `[−1.0, +1.0]` and capped at `1.0` cumulative per episode.

---

## Baseline Scores

Scores produced by running `inference.py` with `gpt-4o-mini` at `temperature=0.0`:

| Task | Name | Score | Avg Steps |
|------|------|-------|-----------|
| 1 | The Dead Link | 1.0 | 3 |
| 2 | The Version Collision | 1.0 | 4 |
| 3 | The Deep CVE Patch | 1.0 | 5 |
| — | **Average** | **1.0** | **4** |

---

## Setup & Usage

### Local Development

```bash
# 1. Clone the repository
git clone https://huggingface.co/spaces/abishek-priyan-369/DevSecOps
cd DevSecOps

# 2. Create a virtual environment
python -m venv env
source env/bin/activate  # Windows: env\Scripts\activate

# 3. Install dependencies
pip install openenv-core pydantic fastapi uvicorn uv openai

# 4. Run the server
ENABLE_WEB_INTERFACE=true uvicorn server.app:app --host 0.0.0.0 --port 8000

# 5. Open the web playground
# Navigate to http://localhost:8000/web
```

### Docker

```bash
# Build the image
docker build -t devsecops-env .

# Run the container
docker run -p 8000:8000 -e ENABLE_WEB_INTERFACE=true devsecops-env
```

### Run Baseline Inference

The script defaults to OpenRouter (an OpenAI-compatible gateway) but works with any OpenAI-compatible endpoint. Judges may override `API_BASE_URL`, `MODEL_NAME`, and the API key via environment variables.

```bash
# Default (OpenRouter):
export API_BASE_URL="https://openrouter.ai/api/v1"
export MODEL_NAME="openai/gpt-4o-mini"
export HF_TOKEN="sk-or-v1-your-key"   # also accepts OPENAI_API_KEY or API_KEY

python inference.py
```

The inference script reads credentials from any of: `HF_TOKEN`, `OPENAI_API_KEY`, or `API_KEY` (in that order). Logs are emitted in spec-compliant `[START]` / `[STEP]` / `[END]` format on stdout.

### Run Tests

```bash
python test_env.py
```

The test suite includes:
- **Functional tests** for all 3 tasks — verifies the legitimate solution path scores 1.00
- **Anti-cheat tests** for all 3 tasks — verifies that destructive deletion exploits are rejected with 0.0, proving the env is exploit-resistant against trivial shortcut strategies

### Connect via Python Client

```python
from client import DevSecOpsEnvClient
from models import DevSecOpsAction

with DevSecOpsEnvClient(base_url="http://localhost:8000").sync() as env:
    obs = env.reset(task_id=1)
    print(f"Initial status: {obs.build_status}")

    env.step(DevSecOpsAction(
        action_type="update_package",
        package_name="requests",
        new_version_specifier="==2.31.0"
    ))

    result = env.step(DevSecOpsAction(action_type="run_validation"))
    print(f"After fix: {result.observation.build_status}")

    result = env.step(DevSecOpsAction(action_type="submit_final_manifest"))
    print(f"Final reward: {result.reward}")
```

---

## Project Structure

```
DevSecOps/
├── inference.py                  # Baseline inference script (mandatory)
├── models.py                     # Pydantic Action + Observation models
├── client.py                     # WebSocket client
├── openenv.yaml                  # Environment manifest
├── pyproject.toml                # Project dependencies
├── Dockerfile                    # Container definition
├── test_env.py                   # Unit tests for all 3 tasks
├── test_realtime.py              # WebSocket real-time tests
└── server/
    ├── app.py                    # FastAPI application
    └── devsecops_environment.py  # Core environment logic
```

---

## Why This Environment Matters

Supply chain security is one of the most critical unsolved problems in modern software engineering. Tools like Dependabot and Snyk can detect vulnerable dependencies, but they cannot reason about complex version constraint conflicts or trace multi-level transitive dependency chains autonomously.

This environment creates a benchmark for training and evaluating AI agents that can do exactly that — replacing hours of manual DevOps work with intelligent, automated dependency resolution.
