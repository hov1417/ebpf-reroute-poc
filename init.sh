tc qdisc add dev wlp59s0 clsact
tc qdisc add dev enx000000000086 clsact
tc filter add dev enx000000000086 ingress bpf da obj ebpf.o sec tc_ingress
tc filter add dev wlp59s0 egress bpf da obj ebpf.o sec tc_egress
