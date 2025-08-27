FROM python:3.12-slim

WORKDIR /app

COPY scope.json .
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY idorscanner/ ./idorscanner/

ENTRYPOINT ["python3", "-m", "idorscanner.main", "--scope", "scope.json"]
