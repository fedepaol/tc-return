FROM fedora:37

RUN dnf install -y procps iputils iproute netcat tcpdump socat procps iptables
