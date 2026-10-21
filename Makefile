.PHONY: install test lint benchmark binary package

PYTHON ?= python

install:
	$(PYTHON) -m pip install -e ".[dev,binary]"
test:
	$(PYTHON) -m pytest -q
lint:
	$(PYTHON) -m ruff check src tests scripts
	$(PYTHON) -m ruff format --check src tests scripts
benchmark:
	$(PYTHON) -m dockroute.benchmark --output outputs/benchmark.json
binary:
	$(PYTHON) scripts/build_binary.py --output outputs
package:
	$(PYTHON) -m build --outdir outputs
