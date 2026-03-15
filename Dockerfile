FROM golang:1.24-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /dns-watchdog .

FROM alpine:3.19
RUN apk --no-cache add ca-certificates
COPY --from=builder /dns-watchdog /usr/local/bin/dns-watchdog

ENTRYPOINT ["dns-watchdog"]
