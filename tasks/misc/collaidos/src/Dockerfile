FROM python:3.11-bookworm

WORKDIR /app

RUN apt update && apt install -y g++

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY collaidos.cpp .
RUN g++ collaidos.cpp -o collaidos

COPY main.py .

ENTRYPOINT [ "python3", "main.py" ]
