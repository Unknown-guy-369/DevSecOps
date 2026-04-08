"""
Baseline inference script for the DevSecOps Dependency Resolver OpenEnv.

This script runs a language model agent (via an OpenAI-compatible API) against
all 3 tasks in the environment and produces reproducible baseline scores.

The default endpoint is OpenRouter (https://openrouter.ai), an OpenAI-compatible
gateway that gives access to dozens of models from different providers (OpenAI,
Anthropic, Meta, Mistral, Google, etc.) through a single endpoint. Judges may
override the endpoint via env vars.

Usage:
    API_BASE_URL=<url> MODEL_NAME=<model> HF_TOKEN=<key> python inference.py

Environment Variables:
    API_BASE_URL  - OpenAI-compatible API endpoint
                    Default: https://openrouter.ai/api/v1
    MODEL_NAME    - Model identifier
                    Default: openai/gpt-4o-mini
    HF_TOKEN      - API key (also accepts OPENAI_API_KEY or API_KEY as fallback)

STDOUT FORMAT (mandatory, single-line per record):
    [START] task=<name> env=<benchmark> model=<model_name>
    [STEP]  step=<n> action=<str> reward=<0.00> done=<true|false> error=<msg|null>
    [END]   success=<true|false> steps=<n> score=<0.00> rewards=<r1,r2,...>
"""

import os
import sys
import json
import re

# ── Optional .env loader (no-op if python-dotenv isn't installed) ────────────
# Judges set env vars directly; this is purely for local development convenience.
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

# ── Environment Variables ────────────────────────────────────────────────────
API_BASE_URL = os.getenv("API_BASE_URL") or "https://openrouter.ai/api/v1"
MODEL_NAME   = os.getenv("MODEL_NAME")   or "openai/gpt-4o-mini"
API_KEY      = os.getenv("HF_TOKEN") or os.getenv("OPENAI_API_KEY") or os.getenv("API_KEY") or ""
BENCHMARK    = "devsecops"

# ── Path Setup ───────────────────────────────────────────────────────────────
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from openai import OpenAI
from models import DevSecOpsAction, DevSecOpsObservation
from server.devsecops_environment import DevSecOpsEnvironment

# ── OpenAI-compatible Client ─────────────────────────────────────────────────
client = OpenAI(
    base_url=API_BASE_URL,
    api_key=API_KEY if API_KEY else "placeholder",
    default_headers={
        "HTTP-Referer": "https://huggingface.co/spaces/abishek-priyan-369/DevSecOps",
        "X-Title": "DevSecOps Dependency Resolver OpenEnv",
    },
)

# ── Constants ────────────────────────────────────────────────────────────────
MAX_STEPS = 15
TEMPERATURE = 0.0

SYSTEM_PROMPT = """You are an expert DevSecOps engineer operating a Python dependency resolver environment.

Your job is to fix dependency issues in a requirements.in file by taking one action at a time.

Available actions — respond with ONLY valid JSON, no other text:

1. Update a package to a specific version:
   {"action_type": "update_package", "package_name": "requests", "new_version_specifier": "==2.31.0"}

2. Remove a conflicting package from the manifest:
   {"action_type": "remove_package", "package_name": "urllib3"}

3. Run validation to check if the manifest resolves cleanly:
   {"action_type": "run_validation"}

4. Submit your final manifest when the build succeeds and all CVEs are patched:
   {"action_type": "submit_final_manifest"}

Strategy:
- If build_status is FAILED: read build_stderr carefully to identify the conflict, then fix it
- If cve_report has entries: upgrade each affected package to the version shown in fixed_in
- Always call run_validation after making changes before submitting
- Only call submit_final_manifest when build_status is SUCCESS and cve_report is empty
- Respond with ONLY the JSON action, nothing else
"""

TASK_DESCRIPTIONS = {
    1: (
        "the_dead_link",
        "Fix a package version that does not exist on PyPI. "
        "The manifest has requests==99.0.0 which is invalid. "
        "Update requests to a real stable version such as 2.31.0."
    ),
    2: (
        "the_version_collision",
        "Fix a version conflict between botocore==1.29.0 and urllib3>=2.0. "
        "botocore 1.29.0 requires urllib3<1.27, but urllib3>=2.0 is also pinned, "
        "making resolution impossible. Remove or adjust the conflicting urllib3 constraint."
    ),
    3: (
        "the_deep_cve_patch",
        "The build succeeds but the manifest contains packages with known CVEs. "
        "requests==2.28.1 has CVE-2023-32681 (fixed in 2.31.0) and "
        "certifi==2022.12.7 has CVE-2023-37920 (fixed in 2023.7.22). "
        "Upgrade both packages to their fixed versions."
    ),
}


# ── Helpers ──────────────────────────────────────────────────────────────────
def action_to_str(a: dict) -> str:
    """Render an action dict as a compact one-line string for the [STEP] log."""
    t = a.get("action_type", "unknown")
    if t == "update_package":
        return f"update_package({a.get('package_name','')},{a.get('new_version_specifier','')})"
    if t == "remove_package":
        return f"remove_package({a.get('package_name','')})"
    if t == "run_validation":
        return "run_validation()"
    if t == "submit_final_manifest":
        return "submit_final_manifest()"
    return t


def get_llm_action(obs: DevSecOpsObservation, task_name: str, task_desc: str, step: int):
    """Ask the LLM to decide the next action. Returns (action_dict, error_or_none)."""
    user_message = (
        f"Task: {task_name}\n"
        f"Description: {task_desc}\n"
        f"Step: {step}/{MAX_STEPS}\n\n"
        f"Current manifest:\n{obs.manifest_content}\n\n"
        f"Build Status: {obs.build_status}\n"
        f"Build Errors:\n{obs.build_stderr if obs.build_stderr else 'None'}\n\n"
        f"Active CVEs: {json.dumps(obs.cve_report, indent=2) if obs.cve_report else 'None'}\n\n"
        f"What is your next action? Respond with ONLY valid JSON."
    )

    try:
        response = client.chat.completions.create(
            model=MODEL_NAME,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user",   "content": user_message},
            ],
            temperature=TEMPERATURE,
            max_tokens=256,
        )
        raw = response.choices[0].message.content.strip()
        json_match = re.search(r'\{.*?\}', raw, re.DOTALL)
        if json_match:
            return json.loads(json_match.group()), None
        return {"action_type": "run_validation"}, "llm_no_json"
    except Exception as e:
        msg = f"llm_error:{type(e).__name__}:{str(e)[:120]}".replace("\n", " ")
        print(f"[WARN] LLM error on step {step}: {e}", file=sys.stderr, flush=True)
        return {"action_type": "run_validation"}, msg


def run_task(task_id: int) -> dict:
    """Run a single task episode and emit spec-compliant [START]/[STEP]/[END] logs."""
    task_name, task_desc = TASK_DESCRIPTIONS[task_id]

    # ── [START] ──────────────────────────────────────────────────────────────
    print(f"[START] task={task_name} env={BENCHMARK} model={MODEL_NAME}", flush=True)

    rewards: list = []
    steps_taken = 0
    final_score = 0.0
    success = False
    last_error: str | None = None
    env = None

    try:
        env = DevSecOpsEnvironment()
        obs = env.reset(task_id=task_id)
        done = False

        for step in range(1, MAX_STEPS + 1):
            if done:
                break

            action_dict, llm_err = get_llm_action(obs, task_name, task_desc, step)

            # Build action object safely
            try:
                action = DevSecOpsAction(**action_dict)
                step_error: str | None = llm_err
            except Exception as e:
                action = DevSecOpsAction(action_type="run_validation")
                action_dict = {"action_type": "run_validation"}
                step_error = f"invalid_action:{e}" if not llm_err else llm_err

            # Execute in environment
            try:
                obs = env.step(action)
                if step_error is None:
                    step_error = None
            except Exception as e:
                step_error = f"step_error:{e}"
                last_error = step_error
                # Emit the failed step then re-raise to finally
                print(
                    f"[STEP] step={step} action={action_to_str(action_dict)} "
                    f"reward=0.00 done=true error={step_error}",
                    flush=True,
                )
                steps_taken = step
                rewards.append(0.0)
                raise

            reward = float(getattr(obs, "reward", 0.0) or 0.0)
            done = bool(getattr(obs, "done", False))
            rewards.append(reward)
            steps_taken = step
            if step_error:
                last_error = step_error

            err_field = step_error if step_error else "null"
            print(
                f"[STEP] step={step} action={action_to_str(action_dict)} "
                f"reward={reward:.2f} done={'true' if done else 'false'} error={err_field}",
                flush=True,
            )

            if done:
                break

        # Final grade from grader
        try:
            final_score = float(env.grade())
        except Exception as e:
            last_error = f"grade_error:{e}"
            final_score = 0.0

        success = final_score >= 0.999

    except Exception as e:
        if last_error is None:
            last_error = f"fatal:{e}"
        print(f"[WARN] task {task_id} fatal: {e}", file=sys.stderr, flush=True)

    finally:
        # ── [END] (always emitted) ───────────────────────────────────────────
        rewards_str = ",".join(f"{r:.2f}" for r in rewards) if rewards else ""
        print(
            f"[END] success={'true' if success else 'false'} "
            f"steps={steps_taken} score={final_score:.2f} rewards={rewards_str}",
            flush=True,
        )

    return {
        "task_id": task_id,
        "task_name": task_name,
        "score": final_score,
        "steps": steps_taken,
        "success": success,
        "rewards": rewards,
    }


def main():
    print("=" * 60, flush=True)
    print("DevSecOps Dependency Resolver — Baseline Inference", flush=True)
    print(f"Model : {MODEL_NAME}", flush=True)
    print(f"API   : {API_BASE_URL}", flush=True)
    print("=" * 60, flush=True)

    results = []
    for task_id in [1, 2, 3]:
        result = run_task(task_id)
        results.append(result)
        print("-" * 60, flush=True)

    # Summary
    avg_score = sum(r["score"] for r in results) / len(results) if results else 0.0
    print("\nFINAL BASELINE RESULTS:", flush=True)
    for r in results:
        print(
            f"  Task {r['task_id']} ({r['task_name']:25s}): "
            f"score={r['score']:.2f}  steps={r['steps']:2d}  "
            f"success={r['success']}",
            flush=True,
        )
    print(f"\n  Average Score : {avg_score:.2f}", flush=True)
    print("=" * 60, flush=True)


if __name__ == "__main__":
    main()
