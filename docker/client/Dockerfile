FROM ubuntu:20.04

# copy client script
WORKDIR /usr/src/client
COPY client.py /usr/src/client/client.py
COPY main.ini /usr/src/client/main.ini
COPY docker-entrypoint.sh /usr/src/client/docker-entrypoint.sh
RUN chmod +x /usr/src/client/docker-entrypoint.sh
RUN apt update && apt install python3 -y && apt install python3-pip -y && pip3 install python-snap7
ENTRYPOINT ["./docker-entrypoint.sh"]
