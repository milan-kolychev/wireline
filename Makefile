# Linux/WSL and CI. On Windows use the PowerShell commands from README.md.
.PHONY: install lint typecheck test unit integration security bench cov clean-start doctor

install:
	pip install -e ".[dev]"

doctor:
	python --version
	python -c "import sys, platform; print(platform.platform())"
	python -c "import pytest, hypothesis; print('test tooling ok')"

lint:
	ruff check src tests benchmarks

typecheck:
	mypy src

unit:
	pytest tests/unit -q

integration:
	pytest tests/integration -q

security:
	pytest -m security -q

test: lint typecheck
	pytest -q

cov:
	pytest --cov=src --cov-report=term-missing --cov-fail-under=80

bench:
	python benchmarks/bench_tcp.py --requests 2000 --payload 1024 --clients 100

clean-start:
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	$(MAKE) install
	$(MAKE) test
