# --- Stage 1: build the Go scanner binary ---
FROM golang:1.24-bookworm AS scanner
WORKDIR /src
COPY tools/scanner/ .
RUN CGO_ENABLED=0 go build -o /out/scanner .

# --- Stage 2: Python runtime ---
FROM python:3.12-slim-bookworm

# libpcap is required by Scapy for packet capture.
RUN apt-get update \
    && apt-get install -y --no-install-recommends libpcap0.8 \
    && rm -rf /var/lib/apt/lists/*

# uv for fast, reproducible dependency installs.
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

WORKDIR /app
COPY pyproject.toml ./
RUN uv pip install --system --no-cache .

COPY . .
COPY --from=scanner /out/scanner /app/tools/scanner/scanner
ENV SCANNER_BIN=/app/tools/scanner/scanner

EXPOSE 8000
CMD ["gunicorn", "-b", "0.0.0.0:8000", "-w", "2", "app:app"]
