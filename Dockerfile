FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY ssh_honeypot.py README.md ./

EXPOSE 22/tcp

CMD ["python3", "/app/ssh_honeypot.py", "--host", "0.0.0.0", "--port", "22", "--host-key", "/data/host_key", "--log-dir", "/data/logs"]
