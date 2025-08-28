FROM python:3.12-slim

WORKDIR /app

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY idorscanner/ ./idorscanner/
COPY scope.json .

RUN mkdir -p /app/results /tmp

RUN useradd -m -u 1000 scanner && \
    chown -R scanner:scanner /app

USER scanner

ENTRYPOINT ["python", "-m", "idorscanner.main"]
CMD ["scan", "/app/scope.json"]
