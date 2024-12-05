#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define HANDSHAKE_MAP_SIZE 1024

struct tcp_session_key {
    __be32 saddr;
    __be32 daddr;
    __be16 sport;
    __be16 dport;
};

struct handshake_status {
    __u64 begin_time;
    __u8 synack_sent;
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, struct tcp_session_key);
    __type(value, struct handshake_status);
    __uint(max_entries, HANDSHAKE_MAP_SIZE);
} pending_handshakes SEC(".maps");

SEC("xdp") 
int xdp_mitigation_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data; //checks Header
    if ((void *)(eth + 1) > data_end)
        return XDP_DROP;

    struct iphdr *ip = (struct iphdr *)(eth + 1); //IP Header
    if ((void *)(ip + 1) > data_end || ip->protocol != IPPROTO_TCP)
        return XDP_DROP;

    struct tcphdr *tcp = (struct tcphdr *)(ip + 1); //TCP header
    if ((void *)(tcp + 1) > data_end)
        return XDP_DROP;

    struct tcp_session_key session = { //struct for session packet
        .saddr = ip->saddr,
        .daddr = ip->daddr,
        .sport = tcp->source,
        .dport = tcp->dest,
    };

    //Mitigation logic here

    return XDP_PASS;

}