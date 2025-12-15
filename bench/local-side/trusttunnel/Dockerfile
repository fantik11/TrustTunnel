# syntax=docker/dockerfile:1
FROM bench-ls

ARG CONAN_VER=2.23.0
ARG GOLANG_VER=1.25.4
ARG LLVM_MAJOR_VER=17

ARG CLIENT_DIR=TrustTunnelClient
ARG NLC_URL="https://github.com/AdguardTeam/NativeLibsCommon.git"
ARG DNS_LIBS_URL="https://github.com/AdguardTeam/DnsLibs.git"

RUN arch=$(arch | sed s/aarch64/arm64/ | sed s/x86_64/amd64/) && \
    apt install -y iptables ninja-build && \
    pip install conan~=$CONAN_VER && \
    ## Install Go
    curl https://dl.google.com/go/go${GOLANG_VER}.linux-${arch}.tar.gz -o /tmp/go.tar.gz && \
    rm -rf /usr/local/go && tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
ENV PATH="/usr/lib/llvm-$LLVM_MAJOR_VER/bin:/usr/local/go/bin:$PATH"

COPY $CLIENT_DIR /bench/$CLIENT_DIR
WORKDIR /bench/$CLIENT_DIR/build
RUN pipreqs . && \
    pip install -r ../scripts/requirements.txt && \
    ../scripts/bootstrap_conan_deps.py
RUN cmake .. -DCMAKE_BUILD_TYPE=Release -G "Ninja" \
        -DCMAKE_C_COMPILER="clang" \
        -DCMAKE_CXX_COMPILER="clang++" \
        -DCMAKE_CXX_FLAGS="-stdlib=libc++"

# fixme: for some reason certificate CN check fails with non-rust endpoint
COPY ssl_verify.patch /bench/

WORKDIR /bench/$CLIENT_DIR
RUN patch -p1 < /bench/ssl_verify.patch && \
    cd build && \
    ninja trusttunnel_client && \
    mv ./trusttunnel/trusttunnel_client /bench/

COPY entrypoint.sh /bench/

WORKDIR /bench/
ENTRYPOINT ["./entrypoint.sh"]
CMD ["endpoint_hostname", "endpoint_ip", "protocol", "mode", "socks_port_first", "socks_port_last"]
