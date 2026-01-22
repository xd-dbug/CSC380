# Stage 1: Build the Go application
FROM golang:1.23-alpine AS builder

# Set the working directory inside the container
WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o retro-game-api RetroGameAPI.go

# Stage 2: Create a minimal final image
FROM alpine:latest

# Set the working directory
WORKDIR /root/

# Copy the binary from the builder stage
COPY --from=builder /app/retro-game-api .

# Expose the port the API runs on
EXPOSE 8080

# Environment variables for database connection
ENV DB_HOST=localhost
ENV DB_PORT=5432
ENV DB_USER=admin
ENV DB_PASSWORD=password
ENV DB_NAME=retro_games

# Command to run the application
CMD ["./retro-game-api"]
