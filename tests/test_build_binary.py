"""Build-script contracts without invoking a heavyweight native compiler."""

import importlib.util
import os
import stat
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path
from types import ModuleType, SimpleNamespace

import pytest


@pytest.fixture
def build():
    script = Path(__file__).resolve().parents[1] / "scripts" / "build_binary.py"
    spec = importlib.util.spec_from_file_location("build_binary", script)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture
def boundary(build, tmp_path, monkeypatch):
    """Model PyInstaller's disk output, retaining real validation and ZIP writing."""
    root = tmp_path / "checkout with spaces"
    (root / "scripts").mkdir(parents=True)
    worker = root / "src" / "dockroute" / "_probe_worker.py"
    worker.parent.mkdir(parents=True)
    worker.write_bytes(b"print('worker source')\n")
    (root / "LICENSE").write_text("license\n", encoding="utf-8")
    (root / "README.md").write_text("readme\n", encoding="utf-8")
    monkeypatch.setattr(build, "__file__", str(root / "scripts" / "build_binary.py"))
    state = SimpleNamespace(
        root=root,
        worker=worker,
        commands=[],
        readers=[],
        worker_content=worker.read_bytes(),
        after_build=lambda bundle: None,
    )

    def run(command, *, check):
        assert check is True
        state.commands.append(command)
        if "PyInstaller" in command:
            destination = Path(command[command.index("--distpath") + 1])
            destination.mkdir(parents=True, exist_ok=True)
            if "--onedir" in command:
                bundle = destination / "dockroute"
                (bundle / "_internal" / "dockroute").mkdir(parents=True)
                (bundle / "_internal" / "python.dll").write_bytes(b"runtime library")
                bundled_worker = bundle / "_internal" / "dockroute" / "_probe_worker.py"
                if state.worker_content is not None:
                    bundled_worker.write_bytes(state.worker_content)
                (bundle / "_internal" / "extra data").mkdir()
                (bundle / "_internal" / "extra data" / "café.txt").write_text(
                    "resource", encoding="utf-8"
                )
            else:
                bundle = destination
            name = "dockroute.exe" if build.os.name == "nt" else "dockroute"
            (bundle / name).write_bytes(b"frozen executable")
            state.after_build(bundle)
        return subprocess.CompletedProcess(command, 0)

    def archive_reader(binary):
        state.readers.append(Path(binary))
        names = [] if state.worker_content is None else ["dockroute\\_probe_worker.py"]
        return SimpleNamespace(toc=names, extract=lambda _name: state.worker_content)

    # PyInstaller is a build extra, not required by the ordinary test environment.
    # Only its external archive-reader boundary is replaced; ZIP and disk reads stay real.
    pyinstaller = ModuleType("PyInstaller")
    archive = ModuleType("PyInstaller.archive")
    readers = ModuleType("PyInstaller.archive.readers")
    pyinstaller.archive = archive
    archive.readers = readers
    readers.CArchiveReader = archive_reader
    monkeypatch.setitem(sys.modules, "PyInstaller", pyinstaller)
    monkeypatch.setitem(sys.modules, "PyInstaller.archive", archive)
    monkeypatch.setitem(sys.modules, "PyInstaller.archive.readers", readers)
    monkeypatch.setattr(build, "subprocess", SimpleNamespace(run=run))
    return state


def invoke(build, monkeypatch, args):
    monkeypatch.setattr(sys, "argv", ["build_binary.py", *args])
    build.main()


def test_default_onefile_keeps_existing_binary_and_archive_paths(
    build, boundary, tmp_path, monkeypatch
):
    destination = tmp_path / "outputs"
    invoke(build, monkeypatch, ["--output", str(destination)])
    command = boundary.commands[0]
    assert "--onefile" in command and "--onedir" not in command
    binary_name = "dockroute.exe" if sys.platform == "win32" else "dockroute"
    assert boundary.commands[1] == [str(destination / binary_name), "--version"]
    assert boundary.commands[2] == [str(destination / binary_name), "doctor", "--help"]
    archive = next(destination.glob("dockroute-*.zip"))
    assert "onedir" not in archive.name
    with zipfile.ZipFile(archive) as bundle:
        assert set(bundle.namelist()) == {binary_name, "LICENSE", "README.md"}
        assert bundle.read(binary_name) == b"frozen executable"


@pytest.mark.parametrize("layout", ["onefile", "onedir"])
def test_explicit_layout_selects_matching_pyinstaller_output(
    build, boundary, tmp_path, monkeypatch, layout
):
    destination = tmp_path / layout
    invoke(build, monkeypatch, ["--layout", layout, "--output", str(destination)])
    command = boundary.commands[0]
    assert f"--{layout}" in command
    other = "onedir" if layout == "onefile" else "onefile"
    assert f"--{other}" not in command
    assert command[command.index("--distpath") + 1] == str(destination)
    if layout == "onedir":
        assert command[command.index("--contents-directory") + 1] == "_internal"
    assert command[command.index("--add-data") + 1].endswith("dockroute")


def test_onedir_archive_contains_whole_bundle_but_not_sibling_files(
    build, boundary, tmp_path, monkeypatch
):
    destination = tmp_path / "directory build"
    destination.mkdir()
    (destination / "unrelated.txt").write_text("do not distribute", encoding="utf-8")
    invoke(build, monkeypatch, ["--layout", "onedir", "--output", str(destination)])
    binary_name = "dockroute.exe" if sys.platform == "win32" else "dockroute"
    assert boundary.commands[1] == [str(destination / "dockroute" / binary_name), "--version"]
    expected_files = {
        f"dockroute/{binary_name}",
        "dockroute/_internal/python.dll",
        "dockroute/_internal/dockroute/_probe_worker.py",
        "dockroute/_internal/extra data/café.txt",
        "LICENSE",
        "README.md",
    }
    if os.name == "nt":
        archive = next(destination.glob("*-onedir.zip"))
        with zipfile.ZipFile(archive) as bundle:
            assert set(bundle.namelist()) == expected_files
            assert (
                bundle.read("dockroute/_internal/dockroute/_probe_worker.py")
                == boundary.worker.read_bytes()
            )
            assert bundle.read("dockroute/_internal/python.dll") == b"runtime library"
    else:
        archive = next(destination.glob("*-onedir.tar.gz"))
        with tarfile.open(archive) as bundle:
            assert {
                member.name for member in bundle.getmembers() if member.isfile()
            } == expected_files
            assert (
                bundle.extractfile("dockroute/_internal/dockroute/_probe_worker.py").read()
                == boundary.worker.read_bytes()
            )
            assert bundle.extractfile("dockroute/_internal/python.dll").read() == b"runtime library"
    assert boundary.readers == [], "onedir data must be read from its actual deployed file"


@pytest.mark.parametrize("layout", ["onefile", "onedir"])
@pytest.mark.parametrize("worker_content", [None, b"outdated worker\n"])
def test_missing_or_stale_worker_prevents_release_archive(
    build, boundary, tmp_path, monkeypatch, layout, worker_content
):
    boundary.worker_content = worker_content
    destination = tmp_path / "outputs"
    with pytest.raises(RuntimeError, match="[Pp]robe worker|[Ee]mbedded probe worker"):
        invoke(build, monkeypatch, ["--layout", layout, "--output", str(destination)])
    assert not list(destination.glob("*.zip")) and not list(destination.glob("*.tar.gz")), (
        "a broken helper must not be packaged"
    )


def test_posix_onedir_tar_preserves_file_and_directory_permissions(
    build, boundary, tmp_path, monkeypatch
):
    # Select the packaging target without changing pathlib's real host implementation.
    monkeypatch.setattr(build, "os", SimpleNamespace(name="posix", pathsep=":"))
    destination = tmp_path / "posix outputs"
    destination.mkdir()
    (destination / "unrelated.txt").write_text("not part of the bundle", encoding="utf-8")
    modes = {}

    def set_permissions(bundle):
        (bundle / "dockroute").chmod(0o751)
        (bundle / "_internal").chmod(0o750)
        # Windows retains its supported permission subset. Compare the actual
        # filesystem metadata rather than assuming POSIX chmod semantics there.
        modes["dockroute/dockroute"] = stat.S_IMODE((bundle / "dockroute").stat().st_mode)
        modes["dockroute/_internal"] = stat.S_IMODE((bundle / "_internal").stat().st_mode)

    boundary.after_build = set_permissions
    invoke(build, monkeypatch, ["--layout", "onedir", "--output", str(destination)])
    archive = next(destination.glob("*-onedir.tar.gz"))
    with tarfile.open(archive) as bundle:
        assert bundle.getmember("dockroute/dockroute").mode == modes["dockroute/dockroute"]
        assert bundle.getmember("dockroute/_internal").mode == modes["dockroute/_internal"]
        assert bundle.getmember("dockroute/_internal").isdir()
        assert bundle.extractfile("dockroute/dockroute").read() == b"frozen executable"
        assert "unrelated.txt" not in bundle.getnames()
        assert not any(member.name.startswith("/") for member in bundle.getmembers())
    checksum = destination / (archive.name + ".sha256")
    assert checksum.is_file()
    assert checksum.read_text(encoding="ascii").endswith("  " + archive.name + "\n")
    assert not list(destination.glob("*.zip"))


def test_posix_onedir_tar_keeps_real_file_and_directory_symlinks(
    build, boundary, tmp_path, monkeypatch
):
    # Probe real link creation first; Windows may require Developer Mode or
    # SeCreateSymbolicLinkPrivilege. Other archive tests still run on Windows.
    capability = tmp_path / "link capability"
    capability.mkdir()
    (capability / "file").write_bytes(b"target")
    (capability / "directory").mkdir()
    try:
        (capability / "file-link").symlink_to("file")
        (capability / "directory-link").symlink_to("directory", target_is_directory=True)
    except OSError as exc:
        pytest.skip(
            f"Host cannot create real file/directory symlinks: os={os.name}, "
            f"errno={exc.errno}, winerror={getattr(exc, 'winerror', None)}; "
            "Windows requires Developer Mode or symlink privilege"
        )
    monkeypatch.setattr(build, "os", SimpleNamespace(name="posix", pathsep=":"))

    def create_links(bundle):
        internal = bundle / "_internal"
        (internal / "library-link").symlink_to("python.dll")
        versions = internal / "Python.framework" / "Versions"
        (versions / "A").mkdir(parents=True)
        (versions / "A" / "resource").write_bytes(b"framework resource")
        (versions / "Current").symlink_to("A", target_is_directory=True)

    boundary.after_build = create_links
    destination = tmp_path / "posix outputs"
    invoke(build, monkeypatch, ["--layout", "onedir", "--output", str(destination)])
    archive = next(destination.glob("*-onedir.tar.gz"))
    with tarfile.open(archive) as bundle:
        file_link = bundle.getmember("dockroute/_internal/library-link")
        directory_link = bundle.getmember("dockroute/_internal/Python.framework/Versions/Current")
        assert file_link.issym() and file_link.linkname == "python.dll"
        assert directory_link.issym() and directory_link.linkname == "A"
        assert (
            bundle.extractfile("dockroute/_internal/Python.framework/Versions/A/resource").read()
            == b"framework resource"
        )
        assert (
            "dockroute/_internal/Python.framework/Versions/Current/resource"
            not in bundle.getnames()
        )


def test_unsupported_layout_fails_before_compiler_or_filesystem_mutations(
    build, boundary, tmp_path, monkeypatch
):
    destination = tmp_path / "unused"
    with pytest.raises(SystemExit) as exc:
        invoke(build, monkeypatch, ["--layout", "invalid", "--output", str(destination)])
    assert exc.value.code == 2
    assert boundary.commands == []
    assert not destination.exists()
