check-docker:
	@python check_docker_ipv6_support.py

build-test-image:
	@docker build -f Dockerfile-test-healthcheck -t docker-dns:test-healthcheck-1.0 .

prepare-test: build-test-image check-docker

test:
	@python -m tests
