bpftool prog load hello.bpf.o /sys/fs/bpf/hello
bpftool net attach xdp pinned /sys/fs/bpf/hello dev wlan0
./hello_usr
