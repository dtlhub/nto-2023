FROM ubuntu:22.04

RUN mkdir -p /service

RUN apt-get update

RUN apt-get install -y socat

WORKDIR /service

COPY ./src ./

RUN useradd nto

USER nto

EXPOSE 749

CMD ["./run.sh"]
