# Data Sentinel conductor - Vantage (V2) - 2026.47.2
#
# The build cycle is the V1 conductor's: requirements.txt, Dockerfile, main.py.
#
#   docker buildx build --platform linux/amd64,linux/arm64 \
#          --build-arg DS_UID=<the scan worker's user id> --build-arg DS_GID=<its group id> \
#          -t ds_conductor:2026.47.2 .
#
# The build context holds: Dockerfile, requirements.txt, main.py, ds_conductor.py,
# ds_connect_lib.py, and - as the scan worker's context does - the Oracle client folder
# instantclient_21_13/ (linux x86-64). Optional: instantclient_arm64/ with a linux arm64
# client. A driver that can't be had does not fail the build: its types then answer
# "checker_missing" and are listed as unavailable at check-in.
#
# Python 3.13 on Debian 13: the newest every worker's dependencies run on (the classify
# worker's flpc holds it at 3.13). See WORKER-STANDARD.md.
FROM python:3.13-slim-trixie

ARG TARGETARCH
# The user the service runs as. NOT root. It must be the user id the scan worker runs as,
# so that a file system check sees exactly what the scanner will see.
ARG DS_UID=10001
ARG DS_GID=10001

ENV DS_SERVICE=ds_conductor \
    DS_SERVICE_EXTERNAL_PORT=5500 \
    DS_SERVICE_EXTERNAL_HOST=ds_conductor \
    DS_ORACLE_CLIENT_DIR=/app/oracle_client \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# --- system libraries -------------------------------------------------------
#  ca-certificates   the system's certificate authorities
#  unixodbc          what pyodbc loads; ODBC Driver 18 plugs into it
#  libaio1t64        what the Oracle client loads. Debian 13 renamed the library, and the
#                    Oracle client still asks for the old name: hence the link.
#  msodbcsql18       ODBC Driver 18 for SQL Server, from Microsoft's repository for Debian 13
#                    (packages for amd64 and arm64)
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl gnupg unixodbc libaio1t64 \
 && AIO="$(find /usr/lib -name 'libaio.so.1t64' | head -n 1)" \
 && if [ -n "$AIO" ]; then ln -sf libaio.so.1t64 "$(dirname "$AIO")/libaio.so.1"; fi \
 && ( curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft-prod.gpg \
      && echo "deb [arch=amd64,arm64 signed-by=/usr/share/keyrings/microsoft-prod.gpg] https://packages.microsoft.com/debian/13/prod trixie main" \
              > /etc/apt/sources.list.d/mssql-release.list \
      && apt-get update \
      && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql18 \
      || ( echo "WARNING: ODBC Driver 18 for SQL Server was not installed; sqlserver will answer checker_missing" \
           && rm -f /etc/apt/sources.list.d/mssql-release.list ) ) \
 && apt-get purge -y --auto-remove curl gnupg \
 && rm -rf /var/lib/apt/lists/*

# --- Oracle Instant Client ----------------------------------------------------
# Copied from the build context, as the scan worker's image does. The bracket in each
# name makes the folder optional: when it isn't in the context, only requirements.txt is
# copied and the build goes on. The client the library loads is /app/oracle_client.
COPY requirements.txt instantclient_21_1[3] /app/instantclient_21_13/
COPY requirements.txt instantclient_arm6[4] /app/instantclient_arm64/
RUN if [ "$TARGETARCH" = "arm64" ]; then ln -sfn /app/instantclient_arm64 /app/oracle_client; \
    else ln -sfn /app/instantclient_21_13 /app/oracle_client; fi \
 && rm -f /app/instantclient_21_13/requirements.txt /app/instantclient_arm64/requirements.txt \
 && echo /app/oracle_client > /etc/ld.so.conf.d/oracle-instantclient.conf \
 && ldconfig

# --- Python packages: every one pinned to an exact version ----------------------
# Wheels only. If one has no wheel for this platform, the rest are installed one at a
# time and the build goes on without it.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --only-binary=:all: -r requirements.txt \
 || ( echo "WARNING: not every package has a wheel for this platform; installing one at a time" \
      && grep '==' requirements.txt | sed 's/ *#.*//' | while read -r PKG; do \
           pip install --no-cache-dir --only-binary=:all: --no-deps "$PKG" || echo "WARNING: NOT INSTALLED: $PKG"; \
         done )

# --- the service ------------------------------------------------------------
COPY main.py ds_conductor.py ds_connect_lib.py /app/

# what this image can check, printed in the build log
RUN python ds_connect_lib.py

RUN if [ "$DS_UID" != "0" ]; then \
      groupadd --gid "$DS_GID" sentinel \
      && useradd --uid "$DS_UID" --gid "$DS_GID" --no-create-home --shell /usr/sbin/nologin sentinel; \
    fi \
 && mkdir -p /mnt/logs && chown "$DS_UID:$DS_GID" /mnt/logs
USER ${DS_UID}:${DS_GID}

# Inside the stack's network only. The stack file publishes NO port for this service and
# nginx has NO location for it: the endpoints have no sign-in.
EXPOSE 5500

HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD python -c "import os, urllib.request; urllib.request.urlopen('http://127.0.0.1:' + os.environ.get('DS_SERVICE_EXTERNAL_PORT', '5500') + '/health', timeout=4)" || exit 1

STOPSIGNAL SIGTERM
CMD ["python", "./main.py"]
