# --- Stage 1: build ---
FROM golang:1.27-alpine AS build
WORKDIR /src

# Copy module files first so Docker can cache downloaded dependencies
COPY go.mod go.sum* ./
RUN go mod download

COPY . .
# Static binary (no cgo), stripped of debug info and local paths
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/firewall ./cmd/firewall

# --- Stage 2: minimal runtime image ---
# Distroless: no shell or package manager, runs as a non-root user
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/firewall /firewall
EXPOSE 8546
ENTRYPOINT ["/firewall"]