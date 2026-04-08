from typing import Dict

from openenv.core import EnvClient
from openenv.core.client_types import StepResult
from openenv.core.env_server.types import State

try:
    from .models import DevSecOpsAction, DevSecOpsObservation
except (ImportError, ModuleNotFoundError):
    from models import DevSecOpsAction, DevSecOpsObservation

class DevSecOpsEnvClient(EnvClient[DevSecOpsAction, DevSecOpsObservation, State]):
    """
    Client for the DevSecOps Dependency Resolver Environment.
    """

    def _step_payload(self, action: DevSecOpsAction) -> Dict:
        """
        Convert DevSecOpsAction to JSON payload for step message.
        """
        return action.model_dump(exclude_none=True)

    def _parse_result(self, payload: Dict) -> StepResult[DevSecOpsObservation]:
        """
        Parse server response into StepResult[DevSecOpsObservation].
        """
        obs_data = payload.get("observation", {})
        
        # Pydantic will auto-parse the dict mapping if structure matches
        observation = DevSecOpsObservation(**obs_data)

        return StepResult(
            observation=observation,
            reward=payload.get("reward"),
            done=payload.get("done", False),
        )

    def _parse_state(self, payload: Dict) -> State:
        """
        Parse server response into State object.
        """
        return State(
            episode_id=payload.get("episode_id"),
            step_count=payload.get("step_count", 0),
        )
