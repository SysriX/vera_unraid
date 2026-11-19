# VERA – VPN Endpoint & Remote Access: WireGuard-Verwaltung für OPNsense
# Neu gebaut, sobald das offizielle Basis-Image (python:3-slim) sich ändert.
ARG PY_TAG=3.13-slim
FROM python:${PY_TAG}

ARG PY_TAG
ARG BASE_DIGEST=unbekannt
ARG QUELLE=https://github.com/
ARG VERSION=1.0.0
LABEL org.opencontainers.image.title="VERA" \
      org.opencontainers.image.description="VPN Endpoint & Remote Access – WireGuard-Zugänge und Standortverbindungen auf OPNsense verwalten" \
      org.opencontainers.image.source="${QUELLE}" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.base.name="docker.io/library/python:${PY_TAG}" \
      org.opencontainers.image.base.digest="${BASE_DIGEST}"

RUN apt-get update \
 && apt-get install -y --no-install-recommends tini \
 && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt && rm /tmp/requirements.txt

COPY app/ /app/
RUN find /app -name '*.py' -exec sed -i 's/\r$//' {} + \
 && python3 -m compileall -q /app

ENV VERA_DATA=/config \
    VERA_PORT=8080 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    TZ=Europe/Berlin
WORKDIR /app
VOLUME /config
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
  CMD python3 -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ.get('VERA_PORT','8080')+'/health',timeout=4)" || exit 1
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python3", "/app/main.py"]
