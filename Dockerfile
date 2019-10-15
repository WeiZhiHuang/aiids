FROM ubuntu
COPY requirement.txt /tmp
RUN apt-get update -qq && apt-get install -yqq python3 python3-pip iproute2 net-tools default-jre libpcap-dev
RUN pip3 install -r /tmp/requirement.txt
