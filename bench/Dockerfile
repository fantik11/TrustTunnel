# syntax=docker/dockerfile:1
FROM python:3.13-slim-bullseye

ARG RUST_CHANNEL=1.85
ARG LLVM_MAJOR_VER=17

# Install the required utilities
RUN apt update && \
    apt install -y build-essential curl git gnupg lsb-release iperf3 iproute2 \
    net-tools software-properties-common wget tar libssl-dev

RUN curl -OL https://github.com/Kitware/CMake/releases/download/v3.31.10/cmake-3.31.10.tar.gz && \
    tar -zxf cmake-3.31.10.tar.gz && cd cmake-3.31.10 && \
    ./bootstrap -- -DCMAKE_BUILD_TYPE:STRING=Release && \
    make -j3 && make install && cd .. \
    rm cmake-3.31.10.tar.gz && rm -rf cmake-3.31.10

## Install LLVM
RUN curl -O https://apt.llvm.org/llvm.sh && \
    chmod +x llvm.sh && \
    ./llvm.sh $LLVM_MAJOR_VER && \
    rm ./llvm.sh && \
    apt install -y libc++-${LLVM_MAJOR_VER}-dev && \
    apt install -y libclang-17-dev && \
    ln -s libc++abi.so.1 /usr/lib/llvm-$LLVM_MAJOR_VER/lib/libc++abi.so
# Install Rust and Cargo
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain ${RUST_CHANNEL}
ENV PATH="/root/.cargo/bin:${PATH}"

CMD bash
