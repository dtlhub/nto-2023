FROM python:3.10-slim as common

WORKDIR /app

COPY requirements.txt .

RUN python3 -m venv /app/env \
    && /app/env/bin/pip install -r requirements.txt

COPY . .

RUN chmod -R 755 /app

USER user

EXPOSE 5000

RUN chown -R root:root flag && chmod 444 flag
USER nobody

CMD ["/app/env/bin/gunicorn", "-w", "4", "-b", "0.0.0.0:5000", "app:app"]
