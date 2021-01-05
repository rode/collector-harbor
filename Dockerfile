# syntax = docker/dockerfile:experimental
# Build the manager binary
FROM golang:1.15-alpine as builder

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
EXPOSE 8080


# - docker build -t rode-collector-harbor:buildID --target=builder
# - copy coverage out
#   - docker run rode-collector-harbor:buildID
#   - docker cp rode-collector-harbor:buildID coverage.txt .
#   - docker rm rode-collector-harbor
# - docker build -t rode-collector-harbor --target=artifact
