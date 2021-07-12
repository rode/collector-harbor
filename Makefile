.PHONY: test fmtcheck vet fmt mocks
GOFMT_FILES?=$$(find . -name '*.go' | grep -v proto)

GO111MODULE=on

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

fmt:
	gofmt -w -s $(GOFMT_FILES)

vet:
	go vet ./...

test: fmtcheck vet
	go test -v ./... -coverprofile=coverage.txt -covermode atomic

mocks:
	go install github.com/maxbrunsfeld/counterfeiter/v6@v6.4.1
	COUNTERFEITER_NO_GENERATE_WARNING="true" go generate ./...
