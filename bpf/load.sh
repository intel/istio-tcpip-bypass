#!/bin/bash

set -x

function load_ebpf {
    bpftool -m prog load bpf_sockops.o "/sys/fs/bpf/bpf_sockops"
    bpftool cgroup attach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"
    MAP_ID=$(bpftool map show |grep "map_redir"| cut -f 1 -d":")
    bpftool map pin id $MAP_ID "/sys/fs/bpf/map_redir"
    MAP_ID=$(bpftool map show |grep "map_proxy"| cut -f 1 -d":")
    bpftool map pin id $MAP_ID "/sys/fs/bpf/map_proxy"
    bpftool -m prog load bpf_redir.o "/sys/fs/bpf/bpf_redir" map name map_proxy pinned "/sys/fs/bpf/map_proxy" map name map_redir pinned "/sys/fs/bpf/map_redir"
    bpftool prog attach pinned "/sys/fs/bpf/bpf_redir" msg_verdict pinned "/sys/fs/bpf/map_redir" pinned "/sys/fs/bpf/map_proxy"
    echo "load bpf programs to bypass tcpip stack"
}

function unload_ebpf {
    bpftool prog detach pinned "/sys/fs/bpf/bpf_redir" msg_verdict pinned "/sys/fs/bpf/map_redir" pinned "/sys/fs/bpf/map_proxy"
    rm -rf "/sys/fs/bpf/bpf_redir"
    bpftool cgroup detach "/sys/fs/cgroup/unified/" sock_ops pinned "/sys/fs/bpf/bpf_sockops"
    rm -rf "/sys/fs/bpf/bpf_sockops"
    rm -rf "/sys/fs/bpf/map_redir"
    rm -rf "/sys/fs/bpf/map_proxy"
    rm -rf "/sys/fs/bpf/map_active_estab"
    rm -rf "/sys/fs/bpf/debug_map"
    echo "unload bpf programs to restore tcpip stack"
}

function finish {
  unload_ebpf
}

if [ ! -n "${BPF_BYPASS_TCPIP}" ]; then
    echo "bpf_bypass_tcpip env is not set"
elif [ "$BPF_BYPASS_TCPIP" = "enabled" ]; then
    load_ebpf
fi

trap finish EXIT
sleep infinity
