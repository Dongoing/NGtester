FROM python:3.12-slim

# pysctp is a C extension over libsctp
RUN apt-get update && apt-get install -y --no-install-recommends \
        libsctp-dev gcc lksctp-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY ngaptester ./ngaptester
COPY config ./config

ENTRYPOINT ["python", "-m", "ngaptester.cli"]
CMD ["--config", "config/open5gs.json", "ng-setup"]
