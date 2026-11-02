# redpent-tools developer shortcuts.
.PHONY: install install-passive tools check test run run-http docker clean

# Install the Python package AND the CLI tools (post-install hook).
install:
	pip install -e ".[dev]"

install-passive:
	REDPENT_INSTALL_LANE=--passive pip install -e ".[dev]"

# (Re)install just the CLI tools for this OS.
tools:
	redpent-tools-install all

check:
	redpent-tools-install --check

test:
	pytest -q

run:
	python -m redpent_tools.server

run-http:
	python -m redpent_tools.server --http

docker:
	docker build -t redpent-tools .

clean:
	rm -rf .venv *.egg-info .pytest_cache __pycache__ redpent_tools/__pycache__ redpent_tools/tools/__pycache__
