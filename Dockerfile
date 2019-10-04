FROM ubuntu
WORKDIR /opt/aiids
COPY . .
RUN apt update -qq && apt install -yqq python3 python3-pip iproute2 net-tools default-jre libpcap-dev
RUN pip3 install -r requirement.txt
CMD sh
