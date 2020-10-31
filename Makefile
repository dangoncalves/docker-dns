prepare-test:
	@docker build -f Dockerfile-test-healthcheck -t docker-dns:test-healthcheck-1.0 .

test:
	@python -m tests
