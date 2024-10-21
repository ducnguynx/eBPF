/*mandatory include*/
#include "packet.h"
#include <linux/types.h>
#include <stddef.h>
#include <linux/bpf.h>
#include <linux/ip.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ipv6.h>
#include <linux/icmpv6.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <linux/icmp.h>

/*User define*/
#define MAX_ENTRIES 10240

/*structure for MAC address*/
struct key {
    __u8 address[6];
};
struct value {
    __u64 timesAppearDest;
    __u64 timesAppearSource;
};

/*define a BPF_MAP_TYPE_HASH*/
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct key);
 __type(value, struct value);
 __uint(pinning, LIBBPF_PIN_BY_NAME);
} xdp_map_count1 SEC(".maps");

/*update HASH_MAP*/
static int updateAddress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return 0;
    }
    struct key key;
/*Destination MAC*/
    key.address[0] = eth->h_dest[0];
    key.address[1] = eth->h_dest[1];
    key.address[2] = eth->h_dest[2];
    key.address[3] = eth->h_dest[3];
    key.address[4] = eth->h_dest[4];
    key.address[5] = eth->h_dest[5];
    struct value *value = bpf_map_lookup_elem(&xdp_map_count1, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppearDest, 1);
    } else {
        struct value newval = {1,0};
        bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
    }
/*Source MAC*/
    key.address[0] = eth->h_source[0];
    key.address[1] = eth->h_source[1];
    key.address[2] = eth->h_source[2];
    key.address[3] = eth->h_source[3];
    key.address[4] = eth->h_source[4];
    key.address[5] = eth->h_source[5];
    value = bpf_map_lookup_elem(&xdp_map_count1, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppearSource, 1);
    } else {
        struct value newval = {0,1};
        bpf_map_update_elem(&xdp_map_count1, &key, &newval, BPF_NOEXIST);
    }
    return XDP_PASS;
}
SEC("xdp")
int ping(struct xdp_md *ctx) {
    long protocol = lookup_protocol(ctx);
    if (protocol == 1) // ICMP 
    {
        bpf_printk("Hello ping");
        // return XDP_DROP; 
    }
    updateAddress(ctx);
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
