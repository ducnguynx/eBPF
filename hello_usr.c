#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
struct key {
    __u8 address[6];
};

struct value {
    __u64 timesAppear;
};

int main() {
    int map_fd = bpf_obj_get("/sys/fs/bpf/xdp_map_count"); // Path to pinned map
    if (map_fd < 0) {
        perror("bpf_obj_get");
        return 1;
    }

    struct key cur_key = {};
    struct key next_key;
    struct value val;

    // Traverse the map using bpf_map_get_next_key() and bpf_map_lookup_elem()
    while (bpf_map_get_next_key(map_fd, &cur_key, &next_key) == 0) {
        if (bpf_map_lookup_elem(map_fd, &next_key, &val) == 0) {
            printf("Address %02x:%02x:%02x:%02x:%02x:%02x, Times %llu\n",
                   next_key.address[0], next_key.address[1], next_key.address[2],
                   next_key.address[3], next_key.address[4], next_key.address[5],
                   val.timesAppear);
        }
        cur_key = next_key;  // Move to the next key
    }

    close(map_fd);
    return 0;
}
