# Stage 1: Build
FROM golang:alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o email-consumer .

# Stage 2: Run
FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY --from=builder /app/email-consumer .
CMD ["./email-consumer"]