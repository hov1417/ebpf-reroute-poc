#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/filter.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stddef.h>

#include "bpf_helpers.h"

#ifdef DEBUG_CODE
#define bpf_printk(fmt, ...)                                                   \
    do {                                                                       \
        static const char _fmt[] = fmt;                                        \
        bpf_trace_printk(_fmt, sizeof(_fmt), ##__VA_ARGS__);                   \
    } while (0)
#endif 
#ifndef DEBUG_CODE
#define bpf_printk(fmt, ...)
#endif 

#define PARSE_HEADERS(SHORT_CIRCUIT)                                           \
    struct ethhdr *eth = (void *)(long)skb->data;                              \
    long ip_ptr = (long)eth + sizeof(struct ethhdr);                           \
    if (ip_ptr + sizeof(struct iphdr) >= skb->data_end) {                      \
        return SHORT_CIRCUIT;                                                  \
    }                                                                          \
    struct iphdr *ip = (void *)ip_ptr;                                         \
    if (ip->protocol != IPPROTO_TCP) {                                         \
        return SHORT_CIRCUIT;                                                  \
    }                                                                          \
    long tcp_ptr = (long)ip + (ip->ihl << 2);                                  \
    if (tcp_ptr >= skb->data_end) {                                            \
        return SHORT_CIRCUIT;                                                  \
    }                                                                          \
    struct tcphdr *tcp = (void *)tcp_ptr;                                      \
    if ((long)tcp + sizeof(struct tcphdr) >= skb->data_end) {                  \
        return SHORT_CIRCUIT;                                                  \
    }

SEC("tc_ingress")
int tc_ingress_(struct __sk_buff *skb) {
    PARSE_HEADERS(TC_ACT_OK);

    __u32 src_port = bpf_ntohs(tcp->source);
    __u32 dst_port = bpf_ntohs(tcp->dest);

    if (src_port != REDIRECT_FROM_PORT) {
        return TC_ACT_OK;
    }

    bpf_printk("INGRESS %pI4:%u -> ", &ip->saddr, src_port);
    bpf_printk("INGRESS         -> %pI4:%u", &ip->daddr, dst_port);

    // changing the source IP
    __u32 old_ip = __bpf_constant_ntohl(REDIRECT_TO_IP);
    __u32 new_ip = __bpf_constant_ntohl(REDIRECT_FROM_IP);
    ip->saddr = new_ip;

    __u32 old_sip = __bpf_constant_ntohl(REDIRECT_TO_SIP);
    __u32 new_sip = __bpf_constant_ntohl(REDIRECT_FROM_SIP);
    ip->daddr = new_sip;

    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_ip,
                        new_ip, sizeof(new_ip));
    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_sip,
                        new_sip, sizeof(new_sip));

    bpf_l4_csum_replace(
        skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check),
        old_ip, new_ip, sizeof(new_ip));
    bpf_l4_csum_replace(
        skb, ETH_HLEN + sizeof(struct iphdr) + offsetof(struct tcphdr, check),
        old_sip, new_sip, sizeof(new_sip));

    // redirecting
    long redirect_res = bpf_redirect(REDIRECT_TO_IFINDEX, BPF_F_INGRESS);
    if (redirect_res != TC_ACT_REDIRECT) {
        bpf_printk("INGRESS redirect failed: %ld", redirect_res);
    }

    bpf_printk("INGRESS ifindex %d", skb->ifindex);
    bpf_printk("INGRESS C %pI4:%u -> ", &ip->saddr, src_port);
    bpf_printk("INGRESS C         -> %pI4:%u", &ip->daddr, dst_port);
    bpf_printk("INGRESS C skb     -> %px", &skb);

    return TC_ACT_OK;
}

SEC("tc_egress")
int tc_egress_(struct __sk_buff *skb) {
    PARSE_HEADERS(TC_ACT_OK);

    __u32 src_port = bpf_ntohs(tcp->source);
    __u32 dst_port = bpf_ntohs(tcp->dest);

    if (dst_port != REDIRECT_TO_PORT) {
        return TC_ACT_OK;
    }

    // changing the destination IP
    __u32 old_ip = __bpf_constant_ntohl(REDIRECT_FROM_IP);
    __u32 new_ip = __bpf_constant_ntohl(REDIRECT_TO_IP);
    ip->daddr = new_ip;

    __u32 old_sip = __bpf_constant_ntohl(REDIRECT_FROM_SIP);
    __u32 new_sip = __bpf_constant_ntohl(REDIRECT_TO_SIP);
    ip->saddr = new_sip;

    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_ip,
                        new_ip, sizeof(new_ip));
    bpf_l3_csum_replace(skb, ETH_HLEN + offsetof(struct iphdr, check), old_sip,
                        new_sip, sizeof(new_sip));

    // redirecting
    long redirect_res = bpf_redirect(REDIRECT_TO_IFINDEX, 0);
    if (redirect_res != TC_ACT_REDIRECT) {
        bpf_printk("EGRESS redirect failed: %ld", redirect_res);
    }

    bpf_printk("EGRESS C %pI4:%u -> ", &ip->saddr, src_port);
    bpf_printk("EGRESS C         -> %pI4:%u", &ip->daddr, dst_port);

    return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
