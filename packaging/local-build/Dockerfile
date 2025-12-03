# -------- Stage 1: Build hostlookuper --------
FROM golang:1.24 AS builder

WORKDIR /src

# Enable Go modules
COPY go.mod go.sum ./
RUN go mod download

# Copy the whole project
COPY . .

# Build for Linux as static binary (needed for distroless)
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -o /hostlookuper .

# -------- Stage 2: Distroless runtime --------
FROM gcr.io/distroless/static-debian11:latest AS runtime
LABEL maintainer="Georgios <gdasky@google.com>"

COPY --from=builder /hostlookuper /hostlookuper

# Run as non-root
USER 65534

ENTRYPOINT ["/hostlookuper"]
