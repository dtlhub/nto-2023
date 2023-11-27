from python:3.11.6-alpine3.17

WORKDIR /app


COPY requirements.txt requirements.txt

RUN pip3 install -r requirements.txt

COPY . .

USER user

CMD ["gunicorn", "--threads=5", "--bind=0.0.0.0:8000", "main:app"]
