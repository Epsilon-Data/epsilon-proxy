BINARY_NAME=epsilon-proxy
VERSION?=0.1.0
LDFLAGS=-ldflags "-X main.Version=$(VERSION)"

.PHONY: build run test clean lint

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/proxy

run: build
	./bin/$(BINARY_NAME) start

test:
	go test -v -race ./...

test-crypto:
	go test -v -race ./internal/crypto/...

clean:
	rm -rf bin/

lint:
	golangci-lint run ./...

deps:
	go mod tidy

install: build
	cp bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
