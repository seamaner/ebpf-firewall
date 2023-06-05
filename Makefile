all:
	clang -g -O2 -target bpf -c bpf.c -o bpf.o
	bpftool prog load ./bpf.o /sys/fs/bpf/cgroup_firewall type cgroup/skb

clean:
	rm -f  bpf.o
