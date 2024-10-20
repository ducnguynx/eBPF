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
    __u64 timesAppear;
};

/*define a BPF_MAP_TYPE_HASH*/
struct {
 __uint(type, BPF_MAP_TYPE_HASH);
 __uint(max_entries, MAX_ENTRIES);
 __type(key, struct key);
 __type(value, struct value);
} xdp_map_count SEC(".maps");

/*update HASH_MAP*/
static int updateAddress(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    struct ethhdr *eth = data;
    if (data + sizeof(struct ethhdr) > data_end) {
        return 0;
    }
    struct key key;
    key.address[0] = eth->h_dest[0];
    key.address[1] = eth->h_dest[1];
    key.address[2] = eth->h_dest[2];
    key.address[3] = eth->h_dest[3];
    key.address[4] = eth->h_dest[4];
    key.address[5] = eth->h_dest[5];
    struct value *value = bpf_map_lookup_elem(&xdp_map_count, &key);
    if (value) {
        __sync_fetch_and_add(&value->timesAppear, 1);
    } else {
        struct value newval = {1};
        bpf_map_update_elem(&xdp_map_count, &key, &newval, BPF_NOEXIST);
    }
    return XDP_PASS;
}
// static void print_stats(void) {
//     struct key cur_key = {};
//     struct key next_key = {};
//     struct value *val;

//     // Traverse the map using bpf_map_get_next_key()
//     while (bpf_map_get_next_key(&xdp_map_count, &cur_key, &next_key) == 0) {
//         val = bpf_map_lookup_elem(&xdp_map_count, &next_key);
//         if (val) {
//             // Print the srcip, packets, and bytes to the BPF trace pipe
//             bpf_printk("Address %02x:%02x:%02x:%02x:%02x:%02x, Times %d", next_key.address[0],next_key.address[1],next_key.address[2],next_key.address[3],next_key.address[4],next_key.address[5], val->timesAppear);
//         }
//         cur_key = next_key;  // Move to the next key
//     }
// }
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
