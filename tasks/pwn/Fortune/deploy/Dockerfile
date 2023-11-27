FROM ubuntu:22.04
RUN mkdir -p /service
RUN apt-get update && apt install -y socat g++
WORKDIR /service
COPY ./src ./
RUN g++ -std=c++14 -o chall chall.cpp
RUN useradd nto
USER nto
EXPOSE 1489

CMD ["./run.sh"]
