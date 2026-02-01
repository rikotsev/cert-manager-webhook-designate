OUTPUT_BINARY=webhook

.PHONY: all
all: clean lint test build

.PHONY: clean
clean:
	rm -rf build

.PHONY: lint
lint:
	golangci-lint run

.PHONY: test
test:
	go test ./... -cover

.PHONY: build
build:
	go build -o dist/${OUTPUT_BINARY} cmd/webhook/main.go