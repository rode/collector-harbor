# syntax = docker/dockerfile:experimental
# go 1.16 is required due to https://github.com/golang/go/commit/25a33daa2b7e7bda773705215113450923ae4815
FROM golang:1.16beta1-alpine as builder

WORKDIR /workspace

RUN apk add --no-cache gcc libc-dev

# Copy the Go Modules manifests
COPY go.mod go.sum /workspace/

# cache deps before building and copying source so that we don't need to re-download as much
# and so that source changes don't invalidate our downloaded layer
RUN go mod download

# Copy the go source
COPY main.go main.go
COPY listener listener
COPY harbor harbor
COPY config config

# Build
RUN --mount=type=cache,target=/root/.cache/go-build CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o rode-collector-harbor

# Test
RUN go test -v -cover -tags unit ./...

# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot as runner
WORKDIR /
COPY --from=builder /workspace/rode-collector-harbor .
USER nonroot:nonroot

ENTRYPOINT ["./rode-collector-harbor"]
