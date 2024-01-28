# syntax=docker/dockerfile:1.4
FROM --platform=$BUILDPLATFORM python:3-alpine AS builder

WORKDIR /app

RUN apk update
RUN apk add pkgconfig
RUN apk add --virtual build-deps gcc python3-dev musl-dev
RUN apk add --no-cache mariadb-dev

COPY requirements.txt /app
RUN pip3 install -r requirements.txt

COPY . /app

ENTRYPOINT ["python3", "-m", "waitress", "--port=8080", "--call", "app:create_app"]

