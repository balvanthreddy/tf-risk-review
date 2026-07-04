.DEFAULT_GOAL := help
PYTHON ?= python3

.PHONY: help install lint format typecheck test test-opa corpus demo clean

help: ## Show available targets
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-14s\033[0m %s\n", $$1, $$2}'

install: ## Install package with dev dependencies
	$(PYTHON) -m pip install -e ".[dev]"

lint: ## Run ruff linter and format check
	ruff check src tests
	ruff format --check src tests

format: ## Auto-format and fix lint issues
	ruff format src tests
	ruff check --fix src tests

typecheck: ## Run mypy
	mypy src

test: ## Run tests (OPA tests skip without the opa binary)
	pytest --cov --cov-report=term-missing

corpus: ## Run the detection corpus only
	pytest tests/corpus -v

demo: ## Review the risky example plan
	tf-risk-review review examples/plans/risky-change.json --format text || true

clean: ## Remove build artifacts and caches
	rm -rf build dist *.egg-info .pytest_cache .mypy_cache .ruff_cache .coverage htmlcov
