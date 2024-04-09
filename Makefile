default:
	true

# Keep things simple, no test driver script.
check:
	./tests/sock-test
	./tests/list-test
	./tests/sign-test
	./tests/status-test
	./tests/daemon-test
	./tests/pid-file-test
	./tests/inetd-test
