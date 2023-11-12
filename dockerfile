# donut, mingw-w64, osslsigncode

FROM python:3.11-slim 

RUN apt-get update && apt-get install -y \
    mingw-w64 \
    osslsigncode \
    gcc \
    make \
    git 

RUN apt install -y -qq make gcc && \
    cd /opt && git clone https://github.com/TheWover/donut.git && \ 
    cd ./donut && \ 
    make

RUN pip3 install colorama && \ 
    pip3 install impacket && \ 
    mkdir /shared 

WORKDIR /shared 
ENTRYPOINT ["/bin/bash"]