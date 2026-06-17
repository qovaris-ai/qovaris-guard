# Conventional targets from the LangChain integration template.

.PHONY: test integration_test build

test:
	uv run --group test pytest tests/unit_tests/

integration_test:
	uv run --group test --group test_integration pytest tests/integration_tests/

build:
	./publish.sh
