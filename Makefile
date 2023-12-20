default:
	true

# Keep things simple, no test driver script.
check:
	./tests/sock-test
	./tests/list-test
	./tests/sign-test
	./tests/status-test
