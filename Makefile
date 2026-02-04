OUTPUT_BINARY=webhook

.PHONY: all setup clean lint test test-e2e build setup-test-assets
all: clean setup lint test build

setup:
	go mod tidy

clean:
	rm -rf build

lint:
	golangci-lint run

test:
	go test ./... -cover

test-e2e:
	$(eval ASSETS_PATH := $(shell go tool setup-envtest use 1.34 -p path))
	KUBEBUILDER_ASSETS="$(ASSETS_PATH)" \
	TEST_ASSET_ETCD="$(ASSETS_PATH)/etcd" \
	TEST_ASSET_KUBE_APISERVER="$(ASSETS_PATH)/kube-apiserver" \
	TEST_ASSET_KUBECTL="$(ASSETS_PATH)/kubectl" \
	TEST_ZONE_NAME="example.com." \
	go test -tags e2e ./cmd/webhook -v

build:
	go build -o dist/${OUTPUT_BINARY} cmd/webhook/main.go