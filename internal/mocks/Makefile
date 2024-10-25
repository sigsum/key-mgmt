MOCK_FILES = signer.go

all: $(MOCK_FILES)

signer.go: ../../pkg/agent/agent.go
	go run github.com/golang/mock/mockgen --destination $@ --package mocks --mock_names Signer=MockSSHSigner sigsum.org/key-mgmt/pkg/agent Signer
