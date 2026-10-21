"""Private opt-in benchmark lease/cancellation channel; absent in normal CLI runs."""

import _thread
import json
import os
import threading
from pathlib import Path
from typing import Callable


class BenchmarkControl:
    def __init__(
        self,
        directory: Path,
        execution_id: str,
        project: str,
        *,
        interrupt: Callable[[], None] = _thread.interrupt_main,
    ):
        if not directory.is_dir():
            raise ValueError("Benchmark control directory must already exist")
        self.directory = directory
        self._lease: dict = {"execution_id": execution_id, "project": project, "helpers": []}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._interrupt = interrupt
        self._write()
        self.thread = threading.Thread(
            target=self._watch, name="dockroute-benchmark-cancel", daemon=True
        )
        self.thread.start()

    def _write(self):
        temporary = self.directory / "lease.tmp"
        with temporary.open("w", encoding="utf-8") as stream:
            json.dump(self._lease, stream)
        os.replace(temporary, self.directory / "lease.json")

    def note_helper(self, name: str, labels: dict[str, str]):
        with self._lock:
            self._lease["helpers"].append({"name": name, "labels": dict(labels)})
            self._write()

    def _watch(self):
        while not self._stop.wait(0.05):
            if (self.directory / "cancel").exists():
                self._interrupt()
                return

    def close(self):
        self._stop.set()
        self.thread.join(timeout=1)
