FROM python:latest

RUN apt-get -y update && apt-get -y upgrade && apt-get install -y socat
RUN pip install pycryptodome

COPY server.py /server.py
COPY flag.py /flag.py

CMD ["socat", "TCP-LISTEN:7550,reuseaddr,fork", "exec:'python3 /server.py'"]
