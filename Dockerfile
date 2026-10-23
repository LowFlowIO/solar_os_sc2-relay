# SC2 reference relay. Build from the repository root:
#   docker build -f relay/Dockerfile -t sc2-relay relay
# (the build context is relay/; the C interop test is not part of the image)
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    SC2_DATA_DIR=/data

RUN groupadd --system sc2 && useradd --system --gid sc2 --home-dir /data --no-create-home sc2 \
    && mkdir -p /data /app && chown sc2:sc2 /data

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

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD python -c "import os,urllib.request; urllib.request.urlopen('http://127.0.0.1:%s/healthz' % os.environ.get('SC2_HTTP_PORT', '8080'), timeout=4)" || exit 1

ENTRYPOINT ["python", "-m", "sc2_relay"]
