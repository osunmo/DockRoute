"""Compose identity and strict local project selection; never pick by popularity."""

import ntpath
import os
from dataclasses import dataclass
from pathlib import Path

import yaml

from dockroute.models import Container
from dockroute.safety import safe_text


class ProjectError(ValueError):
    pass


@dataclass(frozen=True)
class ComposeLabels:
    project: str
    service: str
    depends_on: tuple[str, ...]
    working_dir: str
    config_files: tuple[str, ...]


def parse_labels(labels: dict[str, str]) -> ComposeLabels | None:
    p = labels.get("com.docker.compose.project", "")
    s = labels.get("com.docker.compose.service", "")
    if not p or not s or labels.get("com.docker.compose.oneoff", "").lower() == "true":
        return None
    deps = labels.get("com.docker.compose.depends_on", "")
    return ComposeLabels(
        p,
        s,
        tuple(sorted({x.split(":")[0] for x in deps.split(",") if x})),
        labels.get("com.docker.compose.project.working_dir", ""),
        tuple(x for x in labels.get("com.docker.compose.project.config_files", "").split(",") if x),
    )


def normalized_path(value: str | Path) -> str:
    value = str(value)
    if len(value) > 1 and value[1] == ":":
        return ntpath.normcase(ntpath.normpath(value)).replace("\\", "/")
    return os.path.normcase(os.path.realpath(value)).replace("\\", "/")


def _local_compose(cwd: Path) -> Path | None:
    for directory in (cwd, *cwd.parents):
        for name in ("compose.yaml", "compose.yml", "docker-compose.yaml", "docker-compose.yml"):
            candidate = directory / name
            if candidate.is_file():
                return candidate
    return None


def select_project(
    containers: list[Container],
    *,
    cwd: Path,
    requested: str | None = None,
    environment: dict[str, str] | None = None,
) -> str:
    effective_environment = environment if environment is not None else os.environ
    projects = sorted({c.project for c in containers})
    requested = requested or effective_environment.get("COMPOSE_PROJECT_NAME")
    if requested:
        if requested not in projects:
            raise ProjectError(
                f"Compose project '{safe_text(requested)}' not found. Check Docker context and start the project."
            )
        return requested
    candidates: set[str] = set()
    path = normalized_path(cwd)
    local_file = _local_compose(cwd)
    for c in containers:
        working = normalized_path(c.working_dir) if c.working_dir else ""
        within_working_dir = working and (
            path == working or path.startswith(working.rstrip("/") + "/")
        )
        same_compose_boundary = not local_file or working == normalized_path(local_file.parent)
        if within_working_dir and same_compose_boundary:
            candidates.add(c.project)
        if local_file and normalized_path(local_file) in {
            normalized_path(x) for x in c.config_files
        }:
            candidates.add(c.project)
    # Only use an explicit local top-level name, never an assumed directory slug.
    if not candidates and local_file:
        try:
            if local_file.stat().st_size > 1024 * 1024:
                raise ValueError("oversized Compose file")
            doc = yaml.safe_load(local_file.read_text(encoding="utf-8"))
            name = doc.get("name") if isinstance(doc, dict) else None
            if isinstance(name, str) and "${" not in name and name in projects:
                candidates.add(name)
        except (OSError, ValueError, yaml.YAMLError):
            pass
    if len(candidates) == 1:
        return next(iter(candidates))
    if len(candidates) > 1:
        raise ProjectError(
            "Current Compose project is ambiguous; use --project. Matching projects: "
            + ", ".join(safe_text(x) for x in sorted(candidates))
        )
    available = ", ".join(safe_text(x) for x in projects) or "none"
    raise ProjectError(
        f"No running or stopped Compose project matches this directory. Use --project NAME. Available projects: {available}"
    )
