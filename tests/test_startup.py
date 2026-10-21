"""Help, version and argument errors must work without runtime dependencies."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Each case executes the real entrypoint in a new interpreter. Pytest's own
# imports cannot satisfy or conceal an eager dependency import in that process.
ISOLATED_ENTRYPOINT = r"""
import importlib.abc
import json
import runpy
import sys

root, entrypoint, arguments = json.loads(sys.argv[1])
sys.path.insert(0, root + '/src')
forbidden = {
    'docker', 'requests', 'yaml', 'dockroute.probes', 'dockroute.diagnostics',
    'dockroute.discovery', 'dockroute.models', 'dockroute.reporting',
    'dockroute._probe_worker',
}

def forbidden_name(name):
    return any(name == prefix or name.startswith(prefix + '.') for prefix in forbidden)

assert not any(forbidden_name(name) for name in sys.modules)

class ImportGuard(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if forbidden_name(fullname):
            raise AssertionError('CLI startup imported runtime dependency: ' + fullname)

sys.meta_path.insert(0, ImportGuard())
sys.argv = ['dockroute', *arguments]
try:
    if entrypoint == 'module':
        runpy.run_module('dockroute', run_name='__main__')
    elif entrypoint == 'script':
        runpy.run_path(root + '/scripts/entrypoint.py', run_name='__main__')
    else:
        from dockroute.cli import main
        raise SystemExit(main())
except SystemExit as exc:
    assert not any(forbidden_name(name) for name in sys.modules)
    raise SystemExit(exc.code)
"""


@pytest.mark.parametrize("entrypoint", ["module", "script", "console"])
@pytest.mark.parametrize(
    "arguments, output",
    [
        (["--version"], "DockRoute"),
        (["--help"], "doctor"),
        (["doctor", "--help"], "--project"),
        (["check", "--help"], "HOST:PORT"),
    ],
)
def test_help_and_version_do_not_import_diagnostic_dependencies(entrypoint, arguments, output):
    result = isolated_cli(entrypoint, arguments)
    assert result.returncode == 0, result.stderr
    assert output in result.stdout
    assert result.stderr == ""


@pytest.mark.parametrize("entrypoint", ["module", "script", "console"])
@pytest.mark.parametrize(
    "arguments, error",
    [
        ([], "required"),
        (["--unknown"], "required"),
        (["missing-command"], "invalid choice"),
        (["doctor", "--timeout", "nan"], "timeout must be"),
        (["doctor", "--unknown"], "unrecognized arguments"),
        (["check", "app"], "required"),
        (["check", "app", "http://user:secret@api:8000/path"], "without credentials"),
        (["check", "app", "api:bad"], "valid HOST:PORT"),
        (["check", "app", "invalid!host:8000"], "valid HOST:PORT"),
        (["check", "app", "[::1"], "valid HOST:PORT"),
        (["check", "app", "api:65536"], "valid HOST:PORT"),
    ],
)
def test_argument_errors_precede_diagnostic_imports(entrypoint, arguments, error):
    result = isolated_cli(entrypoint, arguments)
    assert result.returncode == 4, result.stderr
    assert error in result.stderr
    assert "secret" not in result.stdout + result.stderr
    assert "Traceback" not in result.stderr


def isolated_cli(entrypoint, arguments):
    return subprocess.run(
        [
            sys.executable,
            "-I",
            "-c",
            ISOLATED_ENTRYPOINT,
            json.dumps([str(ROOT), entrypoint, arguments]),
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
