FROM golang:1.25-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./

RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o retro-game-api RetroGameAPI.go


FROM alpine:latest
WORKDIR /root/
COPY --from=builder /app/retro-game-api .
EXPOSE 8080

CMD ["./retro-game-api"]
