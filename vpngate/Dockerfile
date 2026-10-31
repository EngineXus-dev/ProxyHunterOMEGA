FROM python:3.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends openvpn iproute2 iptables ca-certificates && rm -rf /var/lib/apt/lists/*
COPY gateway.py /app/gateway.py
CMD ["python", "-u", "/app/gateway.py"]
