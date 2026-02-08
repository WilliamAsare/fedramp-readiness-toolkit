.PHONY: help install dev lint format test validate clean baselines

help: ## Show this help message
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install the toolkit and dependencies
	pip install -e .

dev: ## Install with development dependencies
	pip install -e ".[dev]"
	pre-commit install

dev-all: ## Install with all cloud providers + dev tools
	pip install -e ".[all-clouds,dev]"

lint: ## Run linters (ruff + mypy)
	ruff check scripts/ tests/
	mypy scripts/ --ignore-missing-imports

format: ## Auto-format code
	black scripts/ tests/
	ruff check --fix scripts/ tests/

test: ## Run test suite
	pytest tests/ -v --tb=short

test-unit: ## Run unit tests only
	pytest tests/unit/ -v -m unit

test-integration: ## Run integration tests only
	pytest tests/integration/ -v -m integration

test-cov: ## Run tests with coverage report
	pytest tests/ -v --cov=scripts --cov-report=html --cov-report=term-missing

validate-oscal: ## Validate all OSCAL documents against FedRAMP rules
	python scripts/oscal_validator.py --input-dir templates/oscal/ --baseline moderate

parse-catalog: ## Parse and display NIST 800-53 Rev 5 catalog summary
	python scripts/catalog_parser.py --baseline moderate --output-format table

gap-analysis: ## Run gap analysis (requires --input flag)
	@echo "Usage: python scripts/gap_analysis.py --baseline moderate --input your-status.yaml --output-dir reports/"

baselines: ## Download latest FedRAMP OSCAL baselines from GSA
	@echo "Downloading FedRAMP Rev 5 OSCAL baselines..."
	@mkdir -p baselines/json baselines/catalogs
	curl -sL "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_HIGH-baseline.json" \
		-o baselines/json/FedRAMP_rev5_HIGH-baseline.json
	curl -sL "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_MODERATE-baseline.json" \
		-o baselines/json/FedRAMP_rev5_MODERATE-baseline.json
	curl -sL "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_LOW-baseline.json" \
		-o baselines/json/FedRAMP_rev5_LOW-baseline.json
	curl -sL "https://raw.githubusercontent.com/GSA/fedramp-automation/master/dist/content/rev5/baselines/json/FedRAMP_rev5_LI-SaaS-baseline.json" \
		-o baselines/json/FedRAMP_rev5_LI-SaaS-baseline.json
	@echo "Downloading NIST SP 800-53 Rev 5 catalog..."
	curl -sL "https://raw.githubusercontent.com/usnistgov/oscal-content/main/nist.gov/SP800-53/rev5/json/NIST_SP-800-53_rev5_catalog.json" \
		-o baselines/catalogs/NIST_SP-800-53_rev5_catalog.json
	@echo "Done. Baselines saved to baselines/"

clean: ## Remove build artifacts and caches
	rm -rf build/ dist/ *.egg-info
	rm -rf .pytest_cache .mypy_cache .ruff_cache
	rm -rf htmlcov/
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true
