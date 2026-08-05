from __future__ import annotations

import json
import subprocess
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[1]
IDENTITY_PATH = REPO_ROOT / "project-identity.json"


def _git(*args: str) -> str:
    return subprocess.check_output(["git", *args], cwd=REPO_ROOT, text=True).strip()


def test_project_identity_matches_repo() -> None:
    identity = json.loads(IDENTITY_PATH.read_text(encoding="utf-8"))

    assert _git("rev-parse", "--show-toplevel").replace("\\", "/") == str(REPO_ROOT).replace("\\", "/")
    assert _git("remote", "get-url", "origin") == identity["repoRemote"]
    assert _git("branch", "--show-current") == "main"

    py_files = list(REPO_ROOT.glob("app/**/*.py")) + list(REPO_ROOT.glob("tests/**/*.py"))
    source_blob = "\n".join(path.read_text(encoding="utf-8") for path in py_files)

    assert identity["projectId"] in IDENTITY_PATH.read_text(encoding="utf-8")
    assert identity["projectName"] in IDENTITY_PATH.read_text(encoding="utf-8")
    assert identity["repoRemote"] in IDENTITY_PATH.read_text(encoding="utf-8")

    for marker in identity["forbiddenMarkers"]:
        assert marker not in source_blob, f"found forbidden marker: {marker}"
