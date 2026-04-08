from typing import Literal, Optional, List, Dict, Any
from pydantic import Field
from openenv.core.env_server.types import Action, Observation

class DevSecOpsAction(Action):
    """Actions the agent can take to interact with the environment."""
    action_type: Literal["update_package", "remove_package", "run_validation", "submit_final_manifest"] = Field(
        ..., description="The type of action to perform."
    )
    package_name: Optional[str] = Field(
        None, description="The name of the package to update or remove."
    )
    new_version_specifier: Optional[str] = Field(
        None, description="The version constraint (e.g., '>=2.28.0'). Required for update_package."
    )

class DevSecOpsObservation(Observation):
    """The current state observed by the agent."""
    manifest_content: str = Field(..., description="The raw content of requirements.in.")
    build_status: str = Field(..., description="'SUCCESS' or 'FAILED' after running validation.")
    build_stderr: str = Field(..., description="Error output if the build fails.")
    cve_report: List[Dict[str, Any]] = Field(..., description="List of active CVEs in the resolved tree.")
