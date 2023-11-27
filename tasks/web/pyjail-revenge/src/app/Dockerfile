FROM python:3.10-slim as common

WORKDIR /app

RUN apt-get update && \
    apt-get -y install gcc mono-mcs && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .

RUN python3 -m venv /app/env \
    && /app/env/bin/pip install -r requirements.txt

COPY . .

RUN gcc getFlag.c -o getFlag
RUN chmod 755 getFlag && chmod u+s getFlag
RUN chmod 700 flag

USER nobody

EXPOSE 5000

CMD ["/app/env/bin/gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]



