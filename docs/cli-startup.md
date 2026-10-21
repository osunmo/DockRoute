# Packaging and startup

Help and version use the ordinary argument parser before loading Docker, YAML,
probe or diagnostic modules. Command-specific imports preserve the CLI behavior
while avoiding unrelated startup work.

Build on each target operating system; PyInstaller does not cross-compile.

```sh
python -m pip install -e ".[dev,binary]"
python scripts/build_binary.py --layout onefile --output outputs/onefile
python scripts/build_binary.py --layout onedir --output outputs/onedir
```

One-file binaries unpack at startup and are convenient to distribute. Directory
builds avoid that extraction step, but the complete directory (including
`_internal`) must travel together. Neither layout guarantees faster Docker
probing. Windows uses `dockroute.exe`; Linux/macOS use `dockroute`.

The benchmark retains raw samples/failures and separates full process wall time
from the shorter diagnosis clock:

```sh
python scripts/benchmark_coldstart.py --help
python scripts/benchmark_latency.py --help
```

Use at least 20 runs with consistent warm-ups for comparisons. Record source
revision, runtime, packaging, Docker/Compose versions and failures. Report
median/IQR for valid executions alongside failure counts. Historical datasets
belong in release/CI artifacts; see [release gates](releasing.md).
