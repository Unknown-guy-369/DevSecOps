"""
FastAPI application for the DevSecOps Environment.
"""

try:
    from openenv.core.env_server.http_server import create_app
except Exception as e:
    raise ImportError("openenv is required for the web interface.") from e

try:
    from ..models import DevSecOpsAction, DevSecOpsObservation
    from .devsecops_environment import DevSecOpsEnvironment
except (ModuleNotFoundError, ImportError):
    from models import DevSecOpsAction, DevSecOpsObservation
    from server.devsecops_environment import DevSecOpsEnvironment

app = create_app(
    DevSecOpsEnvironment,
    DevSecOpsAction,
    DevSecOpsObservation,
    env_name="devsecops",
    max_concurrent_envs=4,
)

def main() -> None:
    """Zero-arg entry point for the OpenEnv DevSecOps server.

    Reads HOST and PORT from environment variables (with sensible defaults)
    so it can be launched by `python -m server.app`, `devsecops-server`, or
    `if __name__ == '__main__'`.
    """
    import os
    import uvicorn
    host = os.environ.get("HOST", "0.0.0.0")
    port = int(os.environ.get("PORT", "8000"))
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    main()
