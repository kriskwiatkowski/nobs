FROM multiarch/debian-debootstrap:armhf-buster

RUN apt-get update -qq
USER root
RUN apt-get install -y make golang
RUN rm -rf /var/lib/apt/lists/*
