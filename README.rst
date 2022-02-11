=======================================
System Requirements
=======================================

* Running Requirement:
    * Minimal: Distribution with kernel version newer than(include) *4.18*
    * Optimal: *Ubuntu2004 with Linux 5.4.0-74-generic*

=======================================
Build Docker Image and Load eBPF Program
=======================================

#. Build docker image::

    $ docker build --network=host -t bpf_bypass_tcpip .

#. Load eBPF program via docker command::

    $ docker run  -v /sys/fs:/sys/fs --net=host --privileged --name tcpip-bypass bpf_bypass_tcpip

#. Load eBPF program via setting up a deamonset::

    $ kubectl apply -f bypass-tcpip-daemonset.yaml

#. Unload eBPF program via destroying Docker container or deamonset
