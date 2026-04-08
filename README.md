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

Modern software projects are regularly paralyzed by **"dependency hell"** — broken package links, conflicting version requirements between transitive dependencies, and critical CVEs hiding deep in the dependency tree. Human DevOps engineers spend hours manually untangling version matrices and testing patches.

This OpenEnv environment simulates exactly that challenge. An AI agent manages a Python `requirements.in` manifest and must resolve dependency conflicts and patch security vulnerabilities using a fast, offline, deterministic validation engine powered by **`uv`** (Astral's Rust-based package manager).

The environment is designed to evaluate an agent's ability to:
- Read and parse structured error output (`uv pip compile` stderr)
- Reason about version constraint mathematics
- Trace CVE vulnerability chains through transitive dependencies
- Make targeted, minimal changes without introducing new regressions

---

## Environment Architecture

| Component | Implementation |
|-----------|---------------|
| Dependency resolver | `uv pip compile` subprocess |
| CVE scanner | In-memory Python dictionary (PyPI Advisory Database subset) |
| Validation speed | < 100ms per `step()` |
| Network access | Disabled — fully offline and deterministic |
| Concurrency | Up to 4 simultaneous sessions |

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

**Expected difficulty:** Easy. A single `update_package` action followed by `run_validation` and `submit_final_manifest` is sufficient.

---

### Task 2 — The Version Collision (Medium)

**Initial manifest:**
```
botocore==1.29.0
urllib3>=2.0
```

**Objective:** `botocore==1.29.0` has a strict transitive requirement of `urllib3<1.27`, which is mathematically incompatible with `urllib3>=2.0`. The agent must parse the conflict trace in `build_stderr`, identify the removable constraint, and delete it so `botocore` can resolve its own compatible `urllib3` version.

**Grader:** Binary — clean build gives `score = 1.0`, otherwise `0.0`.

**Expected difficulty:** Medium. Requires reading and reasoning about the conflict trace.

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

**Expected difficulty:** Hard. Requires reading CVE metadata and upgrading multiple packages without breaking the build.

---

## Reward Function

The environment provides dense, shaped rewards throughout the episode:

| Event | Reward |
|-------|--------|
| `run_validation` reduces error line count vs. previous step | `+0.2` |
| `run_validation` increases error line count (regression) | `−0.1` |
| CVE removed from `cve_report` without breaking the build | `+0.2` per CVE |
| `submit_final_manifest` on a perfect state (build OK + no CVEs) | `+0.5` bonus |
| Invalid `update_package` call (missing name or specifier) | `−0.05` |

All rewards are capped at `1.0` per episode.

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

```bash
export API_BASE_URL="https://api.openai.com/v1"
export MODEL_NAME="gpt-4o-mini"
export HF_TOKEN="your-openai-api-key"

python inference.py
```

### Run Tests

```bash
python test_env.py
```

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
