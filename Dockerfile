FROM --platform=$BUILDPLATFORM golang:1.25.1-alpine AS deps

COPY go.mod go.sum ./

RUN go mod download

FROM --platform=$BUILDPLATFORM deps AS builder

ARG TARGETOS
ARG TARGETARCH

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
        -ldflags="-w -s" \
        -o /webhook cmd/webhook/main.go

FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /

COPY --from=builder /webhook /webhook

USER 65532:65532

ENTRYPOINT ["/webhook"]



