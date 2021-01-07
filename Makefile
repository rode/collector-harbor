.PHONY: generate tools test fmtcheck vet fmt
GOFMT_FILES?=$$(find . -name '*.go' | grep -v proto)

GO111MODULE=on

tools:
	go generate ./tools

generate:
	docker build . -t ghcr.io/liatrio/rode-collector-harbor:latest
	docker run -it --rm -v $$(pwd):/workspace ghcr.io/liatrio/rode-collector-harbor:latest

fmtcheck:
	lineCount=$(shell gofmt -l -s $(GOFMT_FILES) | wc -l | tr -d ' ') && exit $$lineCount

fmt:
	gofmt -w -s $(GOFMT_FILES)

vet:
	go vet ./...

test: fmtcheck vet
	go test -v ./... -coverprofile=coverage.txt -covermode atomic
