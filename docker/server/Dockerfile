FROM ubuntu:20.04

# install suricata from local folder with our custom rules
WORKDIR /usr/src/suricata
COPY ./suricata /usr/src/suricata
RUN apt update && apt install gcc -y && apt install g++ -y && DEBIAN_FRONTEND="noninteractive" apt -y install tzdata && apt install -y pkg-config && apt install libpcre2-dev -y && apt install libyaml-dev -y && apt install libjansson-dev -y && apt install libpcap-dev -y && apt install rustc cargo -y && apt install build-essential -y && apt install zlib1g-dev -y && ./configure && make && make install-full

# copy server script
WORKDIR /usr/src/server
COPY server.py /usr/src/server/server.py
COPY main.ini /usr/src/server/main.ini
COPY docker-entrypoint.sh /usr/src/server/docker-entrypoint.sh
RUN chmod +x /usr/src/server/docker-entrypoint.sh
RUN apt update && apt install python3 -y && apt install python3-pip -y && pip3 install python-snap7
EXPOSE 102
ENTRYPOINT ["./docker-entrypoint.sh"]
