"""Prepare pinned development sources, private env copies, or five live recipes.

No images are built and no containers are started. Network access is opt-in::

    python scripts/prepare_corpus.py --lock outputs/corpus-development-lock.json \
        --snapshots work/reproduction/snapshots --destination work/reproduction/files \
        --stage files-only --fetch
    python scripts/prepare_corpus.py --lock outputs/corpus-development-lock.json \
        --snapshots work/reproduction/snapshots --destination work/reproduction/live \
        --stage live

Every destination must be new and below workspace/work. Raw Git/Compose output,
sample env values, and resolved Compose documents remain private there.
"""

from __future__ import annotations

import argparse
import copy
import hashlib
import importlib.util
import json
import os
import re
import shutil
import subprocess
import uuid
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

REPOSITORIES = {
    "awesome-compose": "docker/awesome-compose",
    "example-voting-app": "dockersamples/example-voting-app",
    "full-stack-fastapi-template": "fastapi/full-stack-fastapi-template",
    "Compose-Examples": "Haxxnet/Compose-Examples",
    "dify": "langgenius/dify",
    "self-hosted": "getsentry/self-hosted",
    "docker-elk": "deviantony/docker-elk",
    "community-edition": "plausible/community-edition",
    "mattermost-docker": "mattermost/docker",
    "penpot": "penpot/penpot",
    "opentelemetry-demo": "open-telemetry/opentelemetry-demo",
}
LIVE_SPECS = {
    "awesome-flask-redis": (
        "web",
        8000,
        r"This webpage has been viewed [0-9]+ time\(s\)",
        [("web", "redis:6379")],
    ),
    "awesome-nginx-nodejs-redis": (
        "nginx",
        80,
        r"Number of visits is: [0-9]+",
        [
            ("web1", "redis:6379"),
            ("web2", "redis:6379"),
            ("nginx", "web1:5000"),
            ("nginx", "web2:5000"),
        ],
    ),
    "awesome-nginx-flask-mongo": (
        "web",
        80,
        r"Hello from the MongoDB client",
        [("backend", "mongo:27017"), ("web", "backend:9091")],
    ),
    "awesome-nginx-flask-mysql": (
        "proxy",
        80,
        r"Blog post #",
        [("backend", "db:3306"), ("proxy", "backend:8000")],
    ),
    "awesome-nginx-golang-postgres": (
        "proxy",
        80,
        r"Blog post #",
        [("backend", "db:5432"), ("proxy", "backend:8000")],
    ),
}
_RESERVED = {"CON", "PRN", "AUX", "NUL"} | {
    f"{prefix}{n}" for prefix in ("COM", "LPT") for n in range(1, 10)
}


def _relative(value, *, dot=False):
    if not isinstance(value, str) or not value or PureWindowsPath(value).drive:
        raise ValueError("path must be relative")
    path = PurePosixPath(value.replace("\\", "/"))
    if path.is_absolute() or ".." in path.parts or (not path.parts and not dot):
        raise ValueError("path must remain inside its source root")
    for part in path.parts:
        if ":" in part or part.rstrip(" .") != part or part.split(".")[0].upper() in _RESERVED:
            raise ValueError("reserved or unsafe path component")
    return path.as_posix()


def validate_lock(lock):
    """Validate metadata without reading repository content or environment values."""
    if not isinstance(lock, dict) or lock.get("partition") != "development":
        raise ValueError("only development locks are accepted")
    if lock.get("schema_version") != "dockroute.corpus-lock/1.0":
        raise ValueError("unsupported development lock schema")
    repos = {}
    for repo in lock.get("repositories", []):
        rid = repo.get("id")
        if rid not in REPOSITORIES or rid in repos:
            raise ValueError("unknown or duplicate development repository")
        if repo.get("canonical_url") != "https://github.com/" + REPOSITORIES[rid]:
            raise ValueError("canonical development repository URL required")
        if not re.fullmatch(r"[0-9a-f]{40}", repo.get("revision", "")):
            raise ValueError("revision must be an exact 40-character commit SHA")
        folder = _relative(repo.get("checkout_folder", rid))
        if "/" in folder:
            raise ValueError("checkout_folder must be one safe component")
        repos[rid] = repo
    if not repos:
        raise ValueError("development repositories are required")
    seen = set()
    for case in lock.get("cases", []):
        cid = case.get("id", "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,79}", cid) or cid in seen:
            raise ValueError("safe unique case id required")
        _relative(cid)
        seen.add(cid)
        repo = repos.get(case.get("repo"))
        if repo is None or case.get("revision") != repo["revision"]:
            raise ValueError("case revision must match its pinned repository")
        if not isinstance(case.get("compose_files"), list) or not case["compose_files"]:
            raise ValueError("compose_files must be nonempty")
        for name in case["compose_files"]:
            _relative(name)
        for field in ("env_example", "env_file", "project_directory"):
            if case.get(field) is not None:
                _relative(case[field], dot=field == "project_directory")
        profiles = case.get("profiles", [])
        if not isinstance(profiles, list) or any(
            not isinstance(p, str) or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", p)
            for p in profiles
        ):
            raise ValueError("profiles must contain safe explicit names")
        inert = case.get("inert_env_keys", [])
        if inert and (cid != "plausible-main" or set(inert) != {"BASE_URL", "SECRET_KEY_BASE"}):
            raise ValueError("unsupported inert environment override")
    for entry in lock.get("source_files", []):
        if entry.get("repo") not in repos:
            raise ValueError("source hash references an unknown repository")
        _relative(entry.get("path"))
        if not re.fullmatch(r"[0-9a-f]{64}", entry.get("sha256", "")):
            raise ValueError("source file SHA256 required")
    return lock


def _link(path):
    try:
        stat = path.lstat()
    except FileNotFoundError:
        return False
    return path.is_symlink() or bool(getattr(stat, "st_file_attributes", 0) & 0x400)


def _bounded(workspace, value):
    root = Path(workspace).resolve()
    candidate = Path(value)
    if not candidate.is_absolute():
        candidate = root / candidate
    try:
        lexical = candidate.relative_to(root)
    except ValueError:
        raise ValueError("path must stay below workspace/work") from None
    _relative(lexical.as_posix())
    if not lexical.parts or lexical.parts[0] != "work":
        raise ValueError("path must stay below workspace/work")
    probe = root
    for component in lexical.parts:
        probe /= component
        if _link(probe):
            raise ValueError("symlink or reparse link is not permitted")
    resolved = candidate.resolve()
    if not resolved.is_relative_to(root / "work"):
        raise ValueError("path escaped workspace/work")
    return resolved


def _io(path):
    value = os.path.abspath(path)
    if os.name != "nt" or value.startswith("\\\\?\\"):
        return value
    return "\\\\?\\UNC\\" + value[2:] if value.startswith("\\\\") else "\\\\?\\" + value


def _reject_links(source):
    for folder, dirs, files in os.walk(_io(source), followlinks=False):
        for name in [*dirs, *files]:
            if _link(Path(folder) / name):
                raise ValueError("source contains a symlink or reparse link")
        dirs[:] = [name for name in dirs if name != ".git"]


class _Commands:
    """Record every Git command and exact private binary streams, including failures."""

    def __init__(self, workspace):
        self.root = _bounded(
            workspace, Path(workspace) / "work/corpus-prepare-raw" / uuid.uuid4().hex
        )
        self.entries = []

    def run(self, argv):
        self.root.mkdir(parents=True, exist_ok=True)
        env = {
            key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")
        }
        env["GIT_TERMINAL_PROMPT"] = "0"
        try:
            result = subprocess.run(argv, capture_output=True, timeout=300, check=False, env=env)
            code, stdout, stderr = result.returncode, result.stdout, result.stderr
        except subprocess.TimeoutExpired as error:
            code, stdout, stderr = None, error.stdout or b"", error.stderr or b""
        except OSError:
            code, stdout, stderr = None, b"", b""
        index = len(self.entries)
        entry = {"argv": argv, "returncode": code, "raw_streams": {}}
        for stream, blob in (("stdout", stdout), ("stderr", stderr)):
            name = f"{index:04d}.{stream}.bin"
            (self.root / name).write_bytes(blob)
            entry["raw_streams"][stream] = {
                "filename": name,
                "sha256": hashlib.sha256(blob).hexdigest(),
                "bytes": len(blob),
            }
        self.entries.append(entry)
        (self.root / "commands.json").write_text(json.dumps(self.entries, indent=2) + "\n")
        if code != 0:
            raise ValueError(f"Git command failed; private raw output: {self.root}")
        return stdout.decode("utf-8", errors="replace").strip()


def fetch_commands(repo, target, workspace):
    """Plan only; fetching a branch/default HEAD is deliberately unnecessary."""
    validate_lock(
        {
            "schema_version": "dockroute.corpus-lock/1.0",
            "partition": "development",
            "repositories": [repo],
            "cases": [],
        }
    )
    target = _bounded(workspace, target)
    prefix = ["git", "-c", "core.longpaths=true"]
    local = prefix + ["-C", str(target)]
    return [
        prefix + ["init", str(target)],
        local + ["remote", "add", "origin", repo["canonical_url"] + ".git"],
        local + ["fetch", "--no-tags", "--depth", "1", "origin", repo["revision"]],
        local + ["checkout", "--detach", repo["revision"]],
    ]


def fetch_snapshot(repo, target, workspace, *, commands=None):
    target = _bounded(workspace, target)
    if target.exists():
        raise ValueError("snapshot target already exists; refusing replacement")
    commands = commands or _Commands(workspace)
    target.parent.mkdir(parents=True, exist_ok=True)
    for argv in fetch_commands(repo, target, workspace):
        commands.run(argv)
    _verify_snapshot(repo, target, commands)
    return target


def _verify_snapshot(repo, target, commands):
    if not (target / ".git").is_dir() or _link(target / ".git"):
        raise ValueError("existing snapshot must be a standalone Git checkout")
    prefix = ["git", "-c", "core.longpaths=true", "-C", str(target)]
    if commands.run(prefix + ["rev-parse", "HEAD"]) != repo["revision"]:
        raise ValueError("existing snapshot revision does not match the lock")
    if commands.run(
        prefix + ["status", "--porcelain", "--untracked-files=all", "--ignored=matching"]
    ):
        raise ValueError("existing snapshot must be clean")


def ensure_snapshots(lock, snapshots, workspace, *, fetch=False, commands=None):
    validate_lock(lock)
    snapshots = _bounded(workspace, snapshots)
    commands = commands or _Commands(workspace)
    roots = {}
    for repo in lock["repositories"]:
        target = _bounded(workspace, snapshots / repo.get("checkout_folder", repo["id"]))
        if not target.exists():
            if not fetch:
                raise ValueError("snapshot unavailable; use --fetch to explicitly enable network")
            fetch_snapshot(repo, target, workspace, commands=commands)
        else:
            _reject_links(target)
            _verify_snapshot(repo, target, commands)
        roots[repo["id"]] = target
    for entry in lock.get("source_files", []):
        actual = hashlib.sha256((roots[entry["repo"]] / entry["path"]).read_bytes()).hexdigest()
        if actual != entry["sha256"]:
            raise ValueError("pinned source file hash mismatch")
    return roots


def _new_destination(workspace, destination):
    target = _bounded(workspace, destination)
    if target.exists():
        raise ValueError("preparation destination already exists; use a new directory")
    return target


def _copy(source, target):
    _reject_links(source)
    shutil.copytree(_io(source), _io(target), ignore=shutil.ignore_patterns(".git"))


def prepare_files(lock, snapshots, destination, workspace):
    validate_lock(lock)
    target = _new_destination(workspace, destination)
    commands = _Commands(workspace)
    roots = ensure_snapshots(lock, snapshots, workspace, commands=commands)
    if any(
        target.is_relative_to(source) or source.is_relative_to(target) for source in roots.values()
    ):
        raise ValueError("source and destination must not overlap")
    prepared = copy.deepcopy(lock)
    changes = []
    for repo in prepared["repositories"]:
        dest = target / repo["id"]
        _copy(roots[repo["id"]], dest)
        repo["root"] = str(dest)
    for case in prepared["cases"]:
        root = target / case["repo"]
        case.update(root=str(root), split="development")
        example = case.get("env_example")
        env = case.get("env_file") or str(PurePosixPath(case["compose_files"][0]).parent / ".env")
        if example:
            src, dst = root / example, root / env
            if not src.is_file():
                raise ValueError("declared environment example is missing")
            if src != dst:
                if dst.exists() and dst.read_bytes() != src.read_bytes():
                    raise ValueError("refusing to replace a different sample env file")
                if not dst.exists():
                    dst.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(_io(src), _io(dst))
                changes.append(
                    {
                        "case_id": case["id"],
                        "action": "copy_sample_env",
                        "source": example,
                        "destination": env,
                        "sha256": hashlib.sha256(dst.read_bytes()).hexdigest(),
                        "values_published": False,
                    }
                )
            case["env_file"] = env
        elif case.get("inert_env_keys"):
            dst = root / env
            if dst.exists():
                raise ValueError("refusing to replace an existing inert env destination")
            dst.write_text(
                "BASE_URL=http://127.0.0.1:8000\nSECRET_KEY_BASE="
                + "dockroute-inert-sample-" * 4
                + "\n",
                encoding="utf-8",
            )
            case["env_file"] = env
            changes.append(
                {
                    "case_id": case["id"],
                    "action": "inert_required_values",
                    "keys": ["BASE_URL", "SECRET_KEY_BASE"],
                    "destination": env,
                    "values_published": False,
                }
            )
    prepared["preparation"] = changes
    prepared["preparation_commands"] = commands.entries
    prepared["private_command_logs"] = str(commands.root)
    (target / "manifest.json").write_text(json.dumps(prepared, indent=2) + "\n", encoding="utf-8")
    return prepared


def _normalizer():
    path = Path(__file__).with_name("evaluate_corpus.py")
    spec = importlib.util.spec_from_file_location("corpus_preparation_normalizer", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.normalize_compose


def prepare_live(lock, snapshots, destination, workspace, *, case_ids=None, normalize=None):
    validate_lock(lock)
    target = _new_destination(workspace, destination)
    selected = list(LIVE_SPECS) if case_ids is None else case_ids
    if (
        not selected
        or len(selected) != len(set(selected))
        or any(cid not in LIVE_SPECS for cid in selected)
    ):
        raise ValueError("only the five declared development live samples are supported")
    cases = {case["id"]: case for case in lock["cases"]}
    if any(cid not in cases or cases[cid]["repo"] != "awesome-compose" for cid in selected):
        raise ValueError("live sample is absent from development lock")
    subset = copy.deepcopy(lock)
    subset["repositories"] = [
        repo for repo in lock["repositories"] if repo["id"] == "awesome-compose"
    ]
    subset["cases"] = [cases[cid] for cid in selected]
    subset["source_files"] = [
        x for x in lock.get("source_files", []) if x["repo"] == "awesome-compose"
    ]
    commands = _Commands(workspace)
    roots = ensure_snapshots(subset, snapshots, workspace, commands=commands)
    if any(
        target.is_relative_to(source) or source.is_relative_to(target) for source in roots.values()
    ):
        raise ValueError("source and destination must not overlap")
    normalize = normalize or _normalizer()
    report: dict[str, Any] = {
        "schema_version": "dockroute.corpus-live-preparation/1.0",
        "cases": [],
        "preparation_commands": commands.entries,
        "private_command_logs": str(commands.root),
    }
    for cid in selected:
        case = cases[cid]
        name = cid.removeprefix("awesome-")
        if case["compose_files"] != [name + "/compose.yaml"]:
            raise ValueError("live sample Compose path differs from declared source recipe")
        source = roots["awesome-compose"] / name
        scratch = target / name
        _copy(source, scratch)
        normalization_case = {
            "id": cid,
            "root": str(scratch),
            "compose_files": ["compose.yaml"],
            "profiles": [],
            "raw_log_directory": "normalization-raw",
        }
        attempt = normalize(normalization_case, timeout=40, base_dir=workspace)
        private = scratch / "normalization-attempt.json"
        private.write_text(json.dumps(attempt, indent=2) + "\n", encoding="utf-8")
        entry = {"id": cid, "status": attempt["status"], "normalization_attempt": str(private)}
        if attempt["status"] == "normalized":
            resolved = scratch / "resolved-compose.json"
            resolved.write_text(json.dumps(attempt["config"], indent=2) + "\n", encoding="utf-8")
            incoming, port, pattern, checks = LIVE_SPECS[cid]
            recipe = {
                "id": cid,
                "upstream": "https://github.com/docker/awesome-compose",
                "revision": case["revision"],
                "root": str(scratch),
                "compose_file": str(resolved),
                "incoming_service": incoming,
                "incoming_port": port,
                "health_path": "/",
                "expected_statuses": [200],
                "expected_body_pattern": pattern,
                "checks": [{"source": src, "target": endpoint} for src, endpoint in checks],
                "source_compose_sha256": hashlib.sha256(
                    (source / "compose.yaml").read_bytes()
                ).hexdigest(),
                "annotations": [
                    "Private source copy; Compose normalization only.",
                    "Live runner must record every runtime isolation transformation.",
                ],
            }
            recipe_path = scratch / "recipe.json"
            recipe_path.write_text(json.dumps(recipe, indent=2) + "\n", encoding="utf-8")
            entry["recipe"] = str(recipe_path)
        report["cases"].append(entry)
    (target / "manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--workspace", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--snapshots", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    parser.add_argument("--stage", choices=("files-only", "live"), default="files-only")
    parser.add_argument(
        "--fetch", action="store_true", help="Fetch missing exact commits from public URLs"
    )
    args = parser.parse_args(argv)
    try:
        lock = validate_lock(json.loads(args.lock.read_text(encoding="utf-8-sig")))
        _new_destination(args.workspace, args.destination)
        fetch_log = None
        if args.fetch:
            fetch_log = _Commands(args.workspace)
            ensure_snapshots(lock, args.snapshots, args.workspace, fetch=True, commands=fetch_log)
        function = prepare_files if args.stage == "files-only" else prepare_live
        report = function(lock, args.snapshots, args.destination, args.workspace)
        if fetch_log is not None:
            report["fetch_commands"] = fetch_log.entries
            report["private_fetch_logs"] = str(fetch_log.root)
            (_bounded(args.workspace, args.destination) / "manifest.json").write_text(
                json.dumps(report, indent=2) + "\n", encoding="utf-8"
            )
        print(
            json.dumps(
                {
                    "cases": len(report["cases"]),
                    "stage": args.stage,
                    "manifest": str(_bounded(args.workspace, args.destination) / "manifest.json"),
                    "environment_values_printed": False,
                }
            )
        )
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "reason": str(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
