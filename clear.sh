tc filter del dev wlp59s0 ingress
tc filter del dev wlp59s0 egress
tc filter del dev enx000000000086 ingress
tc filter del dev enx000000000086 egress
tc qdisc del dev wlp59s0 clsact
tc qdisc del dev enx000000000086 clsact
