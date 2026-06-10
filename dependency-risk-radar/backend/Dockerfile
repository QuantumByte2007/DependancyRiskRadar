FROM python:3.11-slim

# System dependencies for androguard and weasyprint
# Note: libgdk-pixbuf2.0-0 was split into libgdk-pixbuf-2.0-0 in Debian Bookworm
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libpangocairo-1.0-0 \
    libgdk-pixbuf-2.0-0 \
    libcairo2 \
    libffi-dev \
    libxml2 \
    libxslt1.1 \
    shared-mime-info \
    default-jdk-headless \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt \
 && pip uninstall -y frida apkinspector 2>/dev/null || true

COPY . .

# Create output directory
RUN mkdir -p /tmp/drr_reports

ENV PYTHONPATH=/app
ENV OUTPUT_DIR=/tmp/drr_reports

EXPOSE 8000

CMD ["uvicorn", "app.api.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
