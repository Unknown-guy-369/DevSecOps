import os
import subprocess
import tempfile
from uuid import uuid4
from typing import Dict, List, Any

from openenv.core.env_server.interfaces import Environment
from openenv.core.env_server.types import State

try:
    from ..models import DevSecOpsAction, DevSecOpsObservation
except (ImportError, ModuleNotFoundError):
    from models import DevSecOpsAction, DevSecOpsObservation

# Mock Vulnerability Database
MOCK_CVE_DB = {
    "certifi": {
        "2022.12.7": [{"id": "CVE-2023-37920", "severity": "HIGH", "desc": "Removal of e-Tugra root certificate", "fixed_in": "2023.7.22"}],
        "2023.5.7": [{"id": "CVE-2023-37920", "severity": "HIGH", "desc": "Removal of e-Tugra root certificate", "fixed_in": "2023.7.22"}],
    },
    "urllib3": {
        "1.26.5": [{"id": "CVE-2023-45803", "severity": "HIGH", "desc": "Request body not stripped on redirect", "fixed_in": "1.26.18"}],
        "1.26.15": [{"id": "CVE-2023-45803", "severity": "HIGH", "desc": "Request body not stripped on redirect", "fixed_in": "1.26.18"}],
    },
    "requests": {
        "2.28.1": [{"id": "CVE-2023-32681", "severity": "MEDIUM", "desc": "Leaking Proxy-Authorization headers", "fixed_in": "2.31.0"}],
        "2.28.2": [{"id": "CVE-2023-32681", "severity": "MEDIUM", "desc": "Leaking Proxy-Authorization headers", "fixed_in": "2.31.0"}],
    },
}

class DevSecOpsState(State):
    task_id: int = 1
    manifest_lines: List[str] = []
    error_lines_count: int = 0
    cves: List[Dict[str, Any]] = []

class DevSecOpsEnvironment(Environment):
    """
    An environment for resolving dependency conflicts and security vulnerabilities.
    """
    SUPPORTS_CONCURRENT_SESSIONS = True

    def __init__(self):
        self._state = DevSecOpsState(episode_id=str(uuid4()), step_count=0)
        self._temp_dir = tempfile.TemporaryDirectory()
        self._state.task_id = 2
        self._state.manifest_lines = []

    def _setup_task(self, task_id: int):
        self._state.task_id = task_id
        if task_id == 1:
            # Task 1: Dead Link - version doesn't exist on PyPI
            self._state.manifest_lines = ["requests==99.0.0"]
        elif task_id == 2:
            # Task 2: Version Collision
            # botocore 1.29.0 requires urllib3<1.27, but we also need urllib3>=2.0
            self._state.manifest_lines = ["botocore==1.29.0", "urllib3>=2.0"]
        elif task_id == 3:
            # Task 3: Deep CVE - builds fine but has vulnerable dependencies
            self._state.manifest_lines = ["requests==2.28.1", "certifi==2022.12.7"]
        else:
            self._state.manifest_lines = []
    
        self._state.error_lines_count = 0
        self._state.cves = []

    def reset(self, task_id: int = 1) -> DevSecOpsObservation: # type: ignore
        """Reset environment to a specific task."""
        self._state = DevSecOpsState(episode_id=str(uuid4()), step_count=0)
        self._setup_task(task_id)
        
        # Initial validation
        obs = self._run_validation_internal()
        return obs

    def step(self, action: DevSecOpsAction) -> DevSecOpsObservation: # type: ignore[override]
        self._state.step_count += 1
        
        reward = 0.0
        done = False
        
        # Action handling
        if action.action_type == "update_package":
            if not action.package_name or not action.new_version_specifier:
                reward -= 0.05
            else:
                found = False
                for i, line in enumerate(self._state.manifest_lines):
                    if line.startswith(action.package_name):
                        self._state.manifest_lines[i] = f"{action.package_name}{action.new_version_specifier}"
                        found = True
                        break
                if not found:
                    self._state.manifest_lines.append(f"{action.package_name}{action.new_version_specifier}")
                    
        elif action.action_type == "remove_package":
            if action.package_name:
                self._state.manifest_lines = [
                    line for line in self._state.manifest_lines 
                    if not line.startswith(action.package_name)
                ]
                
        elif action.action_type == "run_validation":
            obs = self._run_validation_internal()
            return obs

        elif action.action_type == "submit_final_manifest":
            obs = self._run_validation_internal()
            grade_score = self.grade()
            if grade_score == 1.0:
                reward += 0.5
            done = True
            obs.reward =min(obs.reward+reward,1.0)
            obs.done = done
            return obs
            
        # For non-validation actions, we return the current unvalidated state
        return DevSecOpsObservation(
            manifest_content="\n".join(self._state.manifest_lines),
            build_status="UNKNOWN",
            build_stderr="",
            cve_report=[],
            reward=reward,
            done=done
        )
        
    def _run_validation_internal(self) -> DevSecOpsObservation:
        req_in_path = os.path.join(self._temp_dir.name, "requirements.in")
        with open(req_in_path, "w") as f:
            f.write("\n".join(self._state.manifest_lines) + "\n")
            
        try:
            # We use standard PyPI but without compiling cache for deterministic errors
            import sys
            uv_bin = os.path.join(os.path.dirname(sys.executable), "uv.exe" if os.name == "nt" else "uv")
            if not os.path.exists(uv_bin):
                uv_bin = "uv" # fallback
            # Force output file so CVE scan can read pinned resolved dependencies.
            uv_args = [uv_bin, "pip", "compile", "requirements.in", "-o", "requirements.txt"]
            result = subprocess.run(
                uv_args,
                cwd=self._temp_dir.name,
                capture_output=True,
                text=True,
                shell=False
            )
            
            build_status = "SUCCESS" if result.returncode == 0 else "FAILED"
            build_stderr = result.stderr
            
            current_error_lines = len(build_stderr.strip().split("\n")) if build_status == "FAILED" else 0
            
            cves = []
            if build_status == "SUCCESS":
                req_txt_path = os.path.join(self._temp_dir.name, "requirements.txt")
                if os.path.exists(req_txt_path):
                    with open(req_txt_path) as f:
                        lines = f.readlines()
                    
                    for line in lines:
                        if "==" in line and not line.startswith("#"):
                            pkg, version = line.split("==")[:2]
                            pkg = pkg.strip().lower()
                            version = version.split()[0].split(";")[0].strip()
                            
                            # Deep CVE task mock implementation
                            if pkg in MOCK_CVE_DB and version in MOCK_CVE_DB[pkg]:
                                for cve in MOCK_CVE_DB[pkg][version]:
                                    cves.append({**cve,"package": pkg})
                            
                            
            
            # Reward shaping
            reward = 0.0
            
            if self._state.step_count > 0:
                if build_status == "FAILED":
                    if current_error_lines < self._state.error_lines_count:
                        reward += 0.2
                    elif current_error_lines > self._state.error_lines_count:
                        reward -= 0.1
                
                previous_cves = self._state.cves
                if len(cves) < len(previous_cves) and build_status == "SUCCESS":
                    reward += 0.2 * (len(previous_cves) - len(cves))
            
            self._state.error_lines_count = current_error_lines
            self._state.cves = cves
            
            return DevSecOpsObservation(
                manifest_content="\n".join(self._state.manifest_lines),
                build_status=build_status,
                build_stderr=build_stderr,
                cve_report=cves,
                reward=reward,
                done=False
            )
            
        except Exception as e:
            return DevSecOpsObservation(
                manifest_content="\n".join(self._state.manifest_lines),
                build_status="FAILED",
                build_stderr=f"Internal Environment Error: {str(e)}",
                cve_report=[],
                reward=0.0,
                done=False
            )
    def grade(self) -> float:
        """Grade the current state of the environment. Returns 0.0 to 1.0."""
        obs = self._run_validation_internal()
        task_id = self._state.task_id
    
        if task_id == 1:
            # Binary: does it build?
            return 1.0 if obs.build_status == "SUCCESS" else 0.0
    
        elif task_id == 2:
            # Binary: does it build without conflicts?
            return 1.0 if obs.build_status == "SUCCESS" else 0.0
    
        elif task_id == 3:
            # Compound: must build AND have no CVEs
            if obs.build_status != "SUCCESS":
                return 0.0
            elif len(obs.cve_report) > 0:
                return 0.5  # Builds but still vulnerable
            else:
                return 1.0  # Perfect: builds and no CVEs
    
        return 0.0

    @property
    def state(self) -> State:
        return self._state
