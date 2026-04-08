# Deploying DevSecOps to Hugging Face Spaces

You have two options to deploy this environment to your Hugging Face Space (`abishek-priyan-369/DevSecOps`). The **OpenEnv CLI** handles compiling and pushing automatically, while the **Git** approach gives you manual file tracking.

### Option 1: The Automated Way (Recommended)
Since we already set up `openenv.yaml` and `server/Dockerfile`, the `openenv` CLI can push directly to your repository in one step. It handles authentication and file uploading automatically.

Ensure you're inside the `c:\meta-hackathon\devsecops` folder, then run:

```powershell
# This uploads the environment, builds the Docker image remotely, and spins up the UI!
c:\meta-hackathon\env\Scripts\openenv.exe push --repo-id abishek-priyan-369/DevSecOps
```

### Option 2: The Manual Git Way

If you prefer to push your source code to the remote repository manually using the `hf` CLI and `git` that you referenced:

**1. Install the `hf` CLI** (if you haven't already):
```powershell
powershell -ExecutionPolicy ByPass -c "irm https://hf.co/cli/install.ps1 | iex"
```

**2. Clone your Space repository:**
```powershell
# Run this inside c:\meta-hackathon
git clone https://huggingface.co/spaces/abishek-priyan-369/DevSecOps
```
*(When prompted for a password, generate an access token with **write** permissions here: https://huggingface.co/settings/tokens)*

**3. Copy local files to the clone:**
Move everything from `c:\meta-hackathon\devsecops` into `c:\meta-hackathon\DevSecOps` (the cloned folder).

**4. Push everything to Hugging Face:**
```powershell
cd DevSecOps
git add .
git commit -m "Deploy initial DevSecOps OpenEnv setup"
git push
```

> [!TIP]
> When it is remotely deployed via either method, Hugging Face will read the `server/Dockerfile` we created, compile the dependencies via `uv`, and expose the public **`/web`** interface!
