FROM ubuntu:18.04

RUN mkdir /build
WORKDIR /build

RUN set -xe; \
  \
  apt update; \
  apt -y install \
    build-essential \
    libntl-dev \
    libntl35 \
  ; \
  apt clean autoclean; \
  apt autoremove -y; \
  rm -rf /var/lib/{apt,dpkg,cache,log}/;

COPY . ./

RUN set -xe; \
  make
