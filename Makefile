BINARY := bin/shuna
GO ?= go

.PHONY: all build test test-race vet tidy clean

all: vet test-race build

build:
	@mkdir -p bin
	$(GO) build -trimpath -o $(BINARY) ./cmd/shuna

test:
	$(GO) test -count=1 ./...

test-race:
	$(GO) test -race -count=1 -v ./...

vet:
	$(GO) vet ./...

tidy:
	$(GO) mod tidy -go=1.24

clean:
	rm -rf bin coverage.out
