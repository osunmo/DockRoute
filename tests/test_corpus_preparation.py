"""Preparation must not escape scratch scope, mutate snapshots, or start applications."""

import importlib.util
import json
import subprocess
from pathlib import Path

import pytest

SCRIPT = Path(__file__).parents[1] / "scripts" / "prepare_corpus.py"


def preparer():
    assert SCRIPT.is_file(), "Reproducible corpus preparation command is missing"
    spec = importlib.util.spec_from_file_location("corpus_preparation", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def fixture_snapshot(tmp_path):
    """Real local git fixture; no fetch/network/Docker is involved."""
    workspace = tmp_path / "workspace"
    source = workspace / "work" / "snapshots" / "awesome-compose"
    sample = source / "flask-redis"
    sample.mkdir(parents=True)
    (sample / "compose.yaml").write_text("services:\n  web:\n    image: example\n")
    (sample / ".env.example").write_bytes(b"SAMPLE_PASSWORD=private-fixture-only\r\n")
    (sample / "app.py").write_text("print('source fixture')\n")
    git = ["git", "-c", "core.longpaths=true"]
    subprocess.run(git + ["init", "--quiet", str(source)], check=True)
    subprocess.run(git + ["-C", str(source), "add", "."], check=True)
    subprocess.run(
        git
        + [
            "-C",
            str(source),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "fixture",
        ],
        check=True,
    )
    revision = subprocess.check_output(
        git + ["-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    lock = {
        "schema_version": "dockroute.corpus-lock/1.0",
        "partition": "development",
        "repositories": [
            {
                "id": "awesome-compose",
                "canonical_url": "https://github.com/docker/awesome-compose",
                "revision": revision,
                "checkout_folder": "awesome-compose",
            }
        ],
        "cases": [
            {
                "id": "awesome-flask-redis",
                "repo": "awesome-compose",
                "revision": revision,
                "compose_files": ["flask-redis/compose.yaml"],
                "project_directory": "flask-redis",
                "profiles": [],
                "env_example": "flask-redis/.env.example",
                "env_file": "flask-redis/.env",
                "oracle_coverage": "partial",
            }
        ],
    }
    return workspace, source, lock


def test_private_env_copy_preserves_source_and_emits_evaluator_manifest(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    target = workspace / "work" / "prepared"
    report = mod.prepare_files(lock, workspace / "work/snapshots", target, workspace)
    copied = target / "awesome-compose/flask-redis/.env"
    assert copied.read_bytes() == b"SAMPLE_PASSWORD=private-fixture-only\r\n"
    assert not (source / "flask-redis/.env").exists()
    assert not (target / "awesome-compose/.git").exists()
    assert report["cases"][0]["root"] == str(target / "awesome-compose")
    assert report["cases"][0]["env_file"] == "flask-redis/.env"
    assert report["cases"][0]["split"] == "development"
    assert "private-fixture-only" not in json.dumps(report)
    assert json.loads((target / "manifest.json").read_text())["cases"] == report["cases"]


@pytest.mark.parametrize("bad", ["../outside", "work/../outside", "C:/outside", "work/nul"])
def test_destination_escape_and_reserved_paths_rejected_before_copy(tmp_path, bad):
    mod = preparer()
    workspace, _, lock = fixture_snapshot(tmp_path)
    with pytest.raises(ValueError):
        mod.prepare_files(lock, workspace / "work/snapshots", workspace / bad, workspace)
    assert not (workspace / "outside").exists()


def test_existing_prepared_destination_is_not_overwritten(tmp_path):
    mod = preparer()
    workspace, _, lock = fixture_snapshot(tmp_path)
    target = workspace / "work/prepared"
    target.mkdir()
    sentinel = target / "keep.txt"
    sentinel.write_text("keep")
    with pytest.raises(ValueError, match="exists"):
        mod.prepare_files(lock, workspace / "work/snapshots", target, workspace)
    assert sentinel.read_text() == "keep"


@pytest.mark.parametrize(
    "field,value",
    [
        ("compose_files", ["../outside.yaml"]),
        ("env_example", "../outside.env"),
        ("project_directory", "../outside"),
    ],
)
def test_lock_paths_are_rejected_before_source_read(tmp_path, field, value):
    mod = preparer()
    _, _, lock = fixture_snapshot(tmp_path)
    lock["cases"][0][field] = value
    with pytest.raises(ValueError):
        mod.validate_lock(lock)


def test_floating_revision_and_non_development_repository_are_refused(tmp_path):
    mod = preparer()
    _, _, lock = fixture_snapshot(tmp_path)
    lock["repositories"][0]["revision"] = "main"
    with pytest.raises(ValueError, match="revision"):
        mod.validate_lock(lock)
    lock["repositories"][0]["revision"] = "a" * 40
    lock["repositories"][0]["canonical_url"] = "https://github.com/supabase/supabase"
    with pytest.raises(ValueError):
        mod.validate_lock(lock)


def test_dirty_or_wrong_revision_snapshot_is_refused(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    (source / "flask-redis/app.py").write_text("changed\n")
    with pytest.raises(ValueError, match="clean"):
        mod.prepare_files(
            lock, workspace / "work/snapshots", workspace / "work/prepared", workspace
        )
    assert not (workspace / "work/prepared").exists()


def test_clean_snapshot_with_different_revision_is_refused(tmp_path):
    mod = preparer()
    workspace, _, lock = fixture_snapshot(tmp_path)
    lock["repositories"][0]["revision"] = "a" * 40
    lock["cases"][0]["revision"] = "a" * 40
    with pytest.raises(ValueError, match="revision"):
        mod.prepare_files(
            lock, workspace / "work/snapshots", workspace / "work/prepared", workspace
        )
    assert not (workspace / "work/prepared").exists()


def test_git_environment_cannot_redirect_the_bounded_snapshot(tmp_path, monkeypatch):
    mod = preparer()
    workspace, _, lock = fixture_snapshot(tmp_path)
    outside = tmp_path / "external-git-directory"
    monkeypatch.setenv("GIT_DIR", str(outside))
    report = mod.prepare_files(
        lock, workspace / "work/snapshots", workspace / "work/prepared", workspace
    )
    assert report["cases"][0]["revision"] == lock["repositories"][0]["revision"]
    assert not outside.exists()


def test_ignored_private_files_make_a_snapshot_ineligible_for_copy(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    (source / ".gitignore").write_text("private.env\n")
    git = ["git", "-c", "core.longpaths=true", "-C", str(source)]
    subprocess.run(git + ["add", ".gitignore"], check=True)
    subprocess.run(
        git
        + [
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "--quiet",
            "-m",
            "ignore private file",
        ],
        check=True,
    )
    revision = subprocess.check_output(git + ["rev-parse", "HEAD"], text=True).strip()
    lock["repositories"][0]["revision"] = revision
    lock["cases"][0]["revision"] = revision
    (source / "private.env").write_text("PRIVATE_PASSWORD=inert-test-only\n")
    with pytest.raises(ValueError, match="clean"):
        mod.prepare_files(
            lock, workspace / "work/snapshots", workspace / "work/prepared", workspace
        )
    assert not (workspace / "work/prepared").exists()


def test_git_metadata_pointer_cannot_escape_the_snapshot(tmp_path, monkeypatch):
    mod = preparer()
    workspace, _, lock = fixture_snapshot(tmp_path)
    source = workspace / "work/snapshots/worktree"
    source.mkdir()
    (source / ".git").write_text("gitdir: " + str(tmp_path / "external-metadata") + "\n")
    lock["repositories"][0]["checkout_folder"] = "worktree"

    def forbidden_git(*args):
        raise AssertionError("Git must not read unowned external metadata")

    monkeypatch.setattr(mod._Commands, "run", forbidden_git)
    with pytest.raises(ValueError, match="standalone"):
        mod.prepare_files(
            lock, workspace / "work/snapshots", workspace / "work/prepared", workspace
        )
    assert not (workspace / "work/prepared").exists()


def test_source_symlink_cannot_copy_an_external_file(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    outside = tmp_path / "outside.txt"
    outside.write_text("must not copy")
    link = source / "flask-redis/linked.txt"
    try:
        link.symlink_to(outside)
    except OSError:
        pytest.skip("Windows session does not permit symlink creation")
    with pytest.raises(ValueError, match="link"):
        mod.prepare_files(
            lock, workspace / "work/snapshots", workspace / "work/prepared", workspace
        )
    assert not (workspace / "work/prepared").exists()


def test_source_junction_cannot_copy_an_external_directory_on_windows(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    import os

    if os.name != "nt":
        pytest.skip("Windows junction-specific check")
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "keep.txt").write_text("must not copy")
    link = source / "flask-redis/linked-dir"
    result = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(outside)], capture_output=True
    )
    if result.returncode:
        pytest.skip("This session cannot create a Windows junction")
    with pytest.raises(ValueError, match="link"):
        mod.prepare_files(
            lock, workspace / "work/snapshots", workspace / "work/prepared", workspace
        )
    assert not (workspace / "work/prepared").exists()
    assert (outside / "keep.txt").read_text() == "must not copy"


def test_fetch_requires_opt_in_and_never_overwrites_existing_snapshot(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    with pytest.raises(ValueError, match="fetch"):
        mod.ensure_snapshots(lock, workspace / "work/missing", workspace, fetch=False)
    with pytest.raises(ValueError, match="exists"):
        mod.fetch_snapshot(lock["repositories"][0], source, workspace)


def test_exact_revision_fetch_plan_has_no_moving_head(tmp_path):
    mod = preparer()
    workspace, _, lock = fixture_snapshot(tmp_path)
    target = workspace / "work/new/awesome-compose"
    commands = mod.fetch_commands(lock["repositories"][0], target, workspace)
    fetch = next(argv for argv in commands if "fetch" in argv)
    assert fetch[-4:] == ["--depth", "1", "origin", lock["repositories"][0]["revision"]]
    checkout = next(argv for argv in commands if "checkout" in argv)
    assert checkout[-2:] == ["--detach", lock["repositories"][0]["revision"]]
    assert all("core.longpaths=true" in argv for argv in commands)
    assert not any("clone" in argv or "main" in argv or "HEAD" in argv for argv in commands)


def test_git_timeout_retains_private_streams_without_values_in_metadata(tmp_path, monkeypatch):
    mod = preparer()
    workspace = tmp_path / "workspace"
    workspace.mkdir()

    def timeout(*args, **kwargs):
        raise subprocess.TimeoutExpired(
            args[0], 300, output=b"private-stdout", stderr=b"private-stderr"
        )

    monkeypatch.setattr(mod.subprocess, "run", timeout)
    commands = mod._Commands(workspace)
    with pytest.raises(ValueError, match="private raw output"):
        commands.run(["git", "rev-parse", "HEAD"])
    assert (commands.root / "0000.stdout.bin").read_bytes() == b"private-stdout"
    assert (commands.root / "0000.stderr.bin").read_bytes() == b"private-stderr"
    assert "private-stderr" not in (commands.root / "commands.json").read_text()


def test_live_recipe_uses_source_consumer_checks_without_starting_docker(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    lock["cases"][0].pop("env_example")
    lock["cases"][0].pop("env_file")
    target = workspace / "work/live-prepared"

    def normalize(case, **kwargs):
        assert Path(case["root"]).is_relative_to(target)
        return {
            "status": "normalized",
            "command_argv": ["docker", "compose", "config"],
            "config": {"services": {"web": {"image": "example"}}},
            "raw_log_status": "captured",
            "raw_logs": {"directory": "private"},
        }

    report = mod.prepare_live(
        lock,
        workspace / "work/snapshots",
        target,
        workspace,
        case_ids=["awesome-flask-redis"],
        normalize=normalize,
    )
    recipe = json.loads(Path(report["cases"][0]["recipe"]).read_text())
    assert recipe["incoming_service"] == "web"
    assert recipe["incoming_port"] == 8000
    assert recipe["checks"] == [{"source": "web", "target": "redis:6379"}]
    assert recipe["revision"] == lock["repositories"][0]["revision"]
    assert recipe["expected_statuses"] == [200]
    assert (source / "flask-redis/app.py").read_text() == "print('source fixture')\n"
    assert Path(recipe["compose_file"]).is_file()


def test_live_normalization_failure_is_retained_without_fabricating_a_recipe(tmp_path):
    mod = preparer()
    workspace, _, lock = fixture_snapshot(tmp_path)
    target = workspace / "work/live-failed"
    report = mod.prepare_live(
        lock,
        workspace / "work/snapshots",
        target,
        workspace,
        case_ids=["awesome-flask-redis"],
        normalize=lambda case, **kwargs: {
            "status": "skipped",
            "error_class": "compose_timeout",
            "command_argv": ["docker", "compose", "config"],
            "raw_log_status": "captured",
        },
    )
    assert report["cases"][0]["status"] == "skipped"
    assert "recipe" not in report["cases"][0]
    attempt = json.loads(Path(report["cases"][0]["normalization_attempt"]).read_text())
    assert attempt["error_class"] == "compose_timeout"


def test_live_copy_cannot_be_prepared_inside_the_pinned_snapshot(tmp_path):
    mod = preparer()
    workspace, source, lock = fixture_snapshot(tmp_path)
    target = source / "new-prepared"
    with pytest.raises(ValueError, match="overlap"):
        mod.prepare_live(
            lock,
            workspace / "work/snapshots",
            target,
            workspace,
            case_ids=["awesome-flask-redis"],
            normalize=lambda case, **kwargs: {"status": "skipped"},
        )
    assert not target.exists()
