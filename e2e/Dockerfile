FROM node:8-stretch

RUN export DEBIAN_FRONTEND=noninteractive && \
        apt-get update && \
        apt-get install -y mongodb jq python3 && \
        apt-get clean && \
        rm -rf /var/lib/apt/lists

WORKDIR /root

RUN git clone https://github.com/snyk/goof && \
        cd goof && \
        npm install

COPY test-script.sh simple_homebase.py agent /root/

ENTRYPOINT bash test-script.sh
