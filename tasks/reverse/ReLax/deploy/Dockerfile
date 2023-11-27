FROM python:3.7-slim-bookworm
COPY main.py .
RUN mkdir templates
COPY templates/ ./templates/
COPY requirements.txt .

RUN apt-get update \
    && apt-get -y install libpq-dev gcc \
    && pip3 install -r requirements.txt
CMD ["python3", "main.py"]