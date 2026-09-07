FROM golang:1.26-alpine AS builder

WORKDIR /app

COPY . .

RUN go mod tidy
RUN go build -o panel .

FROM alpine:latest

WORKDIR /app

RUN apk add --no-cache ca-certificates curl unzip

# Install cloudflared
RUN curl -L \
    https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64 \
    -o /usr/local/bin/cloudflared \
    && chmod +x /usr/local/bin/cloudflared

# Install Xray 26.3.27
RUN curl -L \
    https://github.com/XTLS/Xray-core/releases/download/v26.3.27/Xray-linux-64.zip \
    -o /tmp/xray.zip \
    && unzip /tmp/xray.zip xray -d /usr/local/bin/ \
    && chmod +x /usr/local/bin/xray \
    && rm -f /tmp/xray.zip

COPY --from=builder /app/panel .

COPY config ./config
COPY static ./static
COPY templates ./templates

RUN mkdir -p data

EXPOSE 8080

CMD ["./panel"]
