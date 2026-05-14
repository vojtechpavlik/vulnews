.PHONY: help install test test-synthetic clean

PYTHON = ./.venv/bin/python3
PIP = ./.venv/bin/pip
PYTEST = ./.venv/bin/pytest

help:
	@echo "Available targets:"
	@echo "  install          Install dependencies in a virtual environment"
	@echo "  test             Run unit and integration tests"
	@echo "  test-synthetic   Run the end-to-end synthetic test (requires local model)"
	@echo "  clean            Remove temporary files and build artifacts"

install:
	python3 -m venv .venv
	$(PIP) install --upgrade pip
	$(PIP) install -e ".[test]"

test:
	$(PYTEST)

test-synthetic:
	@echo "Starting local RSS server..."
	python3 -m http.server 8000 --bind 127.0.0.1 > server.log 2>&1 & echo $$! > server.pid
	@sleep 2
	@echo "Running vulnews synthetic test..."
	@rm -rf state_synthetic
	-$(PYTHON) -m vulnews -c config_synthetic.yaml --one-shot --verbose
	@echo "Shutting down local RSS server..."
	@if [ -f server.pid ]; then kill $$(cat server.pid) && rm server.pid; fi

clean:
	rm -rf .pytest_cache .venv build dist *.egg-info
	rm -f server.log server.pid report.log report_final.log report_realtime.log
	rm -rf state state_synthetic
	find . -type d -name "__pycache__" -exec rm -rf {} +
