FROM golang:1.23-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.Version=$(VERSION)" -o /epsilon-proxy ./cmd/proxy

FROM alpine:3.19

RUN apk add --no-cache ca-certificates

# Install rathole
ARG RATHOLE_VERSION=0.5.0
RUN wget -qO- https://github.com/rapiz1/rathole/releases/download/v${RATHOLE_VERSION}/rathole-x86_64-unknown-linux-musl.zip \
    | unzip -d /usr/local/bin - && chmod +x /usr/local/bin/rathole

COPY --from=builder /epsilon-proxy /usr/local/bin/epsilon-proxy

ENTRYPOINT ["epsilon-proxy"]
CMD ["start"]
