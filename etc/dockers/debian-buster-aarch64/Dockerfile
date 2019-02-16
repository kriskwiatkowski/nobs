FROM multiarch/debian-debootstrap:arm64-buster-slim

RUN apt-get update -qq
USER root
RUN apt-get install -y make golang
RUN rm -rf /var/lib/apt/lists/*
