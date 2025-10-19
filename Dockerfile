# syntax=docker/dockerfile:1
# Stage 1: Build
FROM golang:1.24-alpine AS builder

WORKDIR /app

RUN apk add --no-cache git

COPY . .

RUN go mod download

RUN go build -o auth-service ./cmd

# Stage 2: Minimal image
FROM alpine:latest
WORKDIR /app

RUN apk add --no-cache ca-certificates

# Копируем бинарник и .env
COPY --from=builder /app/auth-service ./
COPY --from=builder /app/.env ./

# Копируем ключи
COPY --from=builder /app/private.pem ./
COPY --from=builder /app/public.pem ./

# Копируем миграции
COPY --from=builder /app/migrations ./migrations

EXPOSE 50051

CMD ["./auth-service"]
