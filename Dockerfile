# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2021 Intel Corporation

FROM golang:1.17 AS allbuild

RUN apt-get update && apt-get install -y \
    make \
    clang \
    llvm \
    libbpf-dev \
    bpftool


WORKDIR /go/src
COPY . /go/src/
RUN go mod download && go get github.com/google/go-licenses
RUN go run github.com/google/go-licenses save "github.com/cilium/ebpf" --save_path=/licenses && \
    install -D /go/src/LICENSE /licenses/tcpip-bypass/LICENSE
RUN go generate && go build -o load-bypass .


FROM gcr.io/distroless/static
COPY --from=allbuild /go/src/load-bypass /bpf/
COPY --from=allbuild /licenses /

WORKDIR /bpf
ENTRYPOINT ["./load-bypass"]
