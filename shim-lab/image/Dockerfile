# kathara-shim: hosts (h1, h2) and the XDP router (r1).
#   docker build -t kathara-shim image/
# Debian bookworm: libbpf 1.1, clang 14, bpftool and Scapy from apt. Builds natively
# on arm64 (Apple Silicon) and amd64.
FROM debian:bookworm
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        bash iproute2 iputils-ping tcpdump ethtool procps net-tools \
        clang llvm make gcc libc6-dev libbpf-dev libelf-dev zlib1g-dev bpftool \
        python3 python3-scapy \
    && rm -rf /var/lib/apt/lists/*
CMD ["bash"]
