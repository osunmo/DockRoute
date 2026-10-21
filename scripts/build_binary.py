"""Build a standalone CLI on the native target OS, including its helper program."""

import argparse
import hashlib
import os
import platform
import subprocess
import sys
import tarfile
import zipfile
from pathlib import Path


def read_worker(reader):
    for name in reader.toc:
        if name.replace("\\", "/") == "dockroute/_probe_worker.py":
            return reader.extract(name)
    raise RuntimeError("Probe worker missing from standalone binary")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path("outputs"))
    parser.add_argument(
        "--layout",
        choices=("onefile", "onedir"),
        default="onefile",
        help="onefile is a single executable; onedir requires the complete dockroute folder",
    )
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    destination = args.output.resolve()
    command = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--noconfirm",
        "--clean",
        f"--{args.layout}",
        "--name",
        "dockroute",
        "--paths",
        str(root / "src"),
        "--distpath",
        str(destination),
        "--workpath",
        str(root / "work" / "pyinstaller"),
        "--specpath",
        str(root / "work"),
        "--add-data",
        str(root / "src/dockroute/_probe_worker.py") + os.pathsep + "dockroute",
        "--hidden-import",
        "docker",
        "--hidden-import",
        "yaml",
        str(root / "scripts/entrypoint.py"),
    ]
    if args.layout == "onedir":
        command.extend(["--contents-directory", "_internal"])
    subprocess.run(command, check=True)
    bundle = destination / "dockroute" if args.layout == "onedir" else destination
    binary = bundle / ("dockroute.exe" if os.name == "nt" else "dockroute")
    subprocess.run([str(binary), "--version"], check=True)
    subprocess.run([str(binary), "doctor", "--help"], check=True)
    # Validate the actual worker used by each frozen layout, before distribution.
    if args.layout == "onefile":
        import PyInstaller.archive.readers

        reader = PyInstaller.archive.readers.CArchiveReader(str(binary))
        worker = read_worker(reader)
    else:
        try:
            worker = (bundle / "_internal/dockroute/_probe_worker.py").read_bytes()
        except FileNotFoundError as exc:
            raise RuntimeError("Probe worker missing from directory bundle") from exc
    if worker != (root / "src/dockroute/_probe_worker.py").read_bytes():
        raise RuntimeError("Embedded probe worker differs from the source worker")
    from dockroute import __version__

    layout_suffix = "-onedir" if args.layout == "onedir" else ""
    posix_directory = args.layout == "onedir" and os.name != "nt"
    archive_suffix = ".tar.gz" if posix_directory else ".zip"
    archive = destination / (
        f"dockroute-{__version__}-{platform.system().lower()}-"
        f"{platform.machine().lower()}{layout_suffix}{archive_suffix}"
    )
    if posix_directory:
        # POSIX PyInstaller bundles rely on file and directory symlinks, notably
        # macOS framework links. Tar retains them and executable permission bits.
        with tarfile.open(archive, "w:gz", dereference=False) as tar:
            tar.add(bundle, arcname="dockroute")
            tar.add(root / "LICENSE", arcname="LICENSE")
            tar.add(root / "README.md", arcname="README.md")
    else:
        with zipfile.ZipFile(archive, "w", compression=zipfile.ZIP_DEFLATED) as z:
            if args.layout == "onefile":
                z.write(binary, binary.name)
            else:
                for path in sorted(bundle.rglob("*")):
                    if path.is_file():
                        z.write(path, path.relative_to(destination).as_posix())
            z.write(root / "LICENSE", "LICENSE")
            z.write(root / "README.md", "README.md")
    archive.with_name(archive.name + ".sha256").write_text(
        hashlib.sha256(archive.read_bytes()).hexdigest() + "  " + archive.name + "\n",
        encoding="ascii",
    )
    print(f"Standalone binary: {binary}\nArchive: {archive}")


if __name__ == "__main__":
    main()
