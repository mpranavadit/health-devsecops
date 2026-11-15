
FROM python:3.11-slim

WORKDIR /app

# Update Debian packages to receive security fixes
RUN apt-get update \
 && apt-get upgrade -y \
 && rm -rf /var/lib/apt/lists/*

# Update Python packaging tools
RUN python -m pip install --no-cache-dir --upgrade pip setuptools wheel
RUN rm -f /usr/local/lib/python3.11/site-packages/pip/_vendor/bom.cdx.json
# Install application dependencies
COPY src/requirements.txt .
RUN python -m pip install --no-cache-dir --retries 10 --timeout 120 --index-url https://pypi.org/simple -r requirements.txt

COPY src/ .

# Non-root user
RUN useradd --no-create-home --uid 10001 --shell /usr/sbin/nologin appuser \
 && mkdir -p /data \
 && chown 10001:10001 /data

USER 10001

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s \
  CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2)"

CMD ["sh", "-c", "python init_db.py && exec gunicorn --bind 0.0.0.0:8000 --workers 2 --access-logfile - app:app"]
