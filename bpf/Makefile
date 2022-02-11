# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0

FLAGS := -O2 -g
CLANG_FLAGS :=  ${FLAGS} -target bpf -emit-llvm
LLC_FLAGS   := -march=bpf -mcpu=probe -mattr=dwarfris
LIB := $(shell find -name '*.h')
CLANG  ?= clang
LLC    ?= llc

BPF = bpf_sockops.o bpf_redir.o
all: $(BPF)

%.ll: %.c $(LIB)
	${CLANG} ${CLANG_FLAGS} -c $< -o $@

$(BPF): %.o: %.ll
	${LLC} ${LLC_FLAGS} -filetype=obj -o $@ $(patsubst %.o,%.ll,$@)

clean:
	rm -fr *.o *.ll *.i
