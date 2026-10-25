# SC2 reference relay. Build from the repository root:
#   docker build -t sc2-relay:0.4.1 .
# (docker-compose.yml uses the same tag; docker compose build also works)
# (the build context is the repository root; tests/ is excluded by .dockerignore)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SC2_DATA_DIR=/data

# Fixed UID/GID 10001 so the certbot sidecar's deploy hook can hand the key
# to the relay (deploy/certbot/deploy-hook.sh, SC2_RELAY_UID/GID).
RUN groupadd --system --gid 10001 sc2 \
    && useradd --system --uid 10001 --gid sc2 --home-dir /data --no-create-home sc2 \
    && mkdir -p /data /app && chown sc2:sc2 /data && chmod 0700 /data

WORKDIR /app
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt
COPY sc2proto /app/sc2proto
COPY sc2_relay /app/sc2_relay
COPY config /app/config

USER sc2
VOLUME ["/data"]
# 7778 chats:// (TLS), 7777 chat:// (plain, off by default), 8080 HTTP, 7780 admin (loopback in the container)
EXPOSE 7778 7777 8080

# /healthz on the HTTP port (HTTPS with SC2_HTTP_TLS); with HTTP off, a TCP
# connect to the client port; healthy while waiting for the first ACME
# certificate (sc2_relay/healthcheck.py)
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD ["python", "-m", "sc2_relay.healthcheck"]

ENTRYPOINT ["python", "-m", "sc2_relay"]
