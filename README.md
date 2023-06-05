# ebpf-fw

A very simple firewall, harnessing the power of eBPFs! The eBPF is attached to the root cgroup and is used to control whether packets are allowed through.

Using cgroup/skb and bpftool.

Requires Linux >= 4.10 (ie. CentOS 8 or Ubuntu 17.04).

Great eBPF reference: <https://docs.cilium.io/en/v1.9/bpf/>


## Requirements

Building requires the following on CentOS 8:
`yum install -y clang llvm `  
or on Ubuntu:
`apt install -y clang llvm make`

Install bpftool: <https://github.com/libbpf/bpftool/blob/master/README.md>


cgroup2 FS must be mounted. By default it looks for it on `/sys/fs/cgroup/unified` but if it's not mounted there you can do:
```
sudo mkdir /mnt/cgroup2
sudo mount -t cgroup2 none /mnt/cgroup2
```
and change the path to `/mnt/cgroup2` in `ebpf-fw.go`


## Building

`make`


## Running

All must run as root.

Load eBPF with:  
 bpftool prog load ./bpf.o /sys/fs/bpf/cgroup_firewall type cgroup/skb`

Attach eBPF to a cgroup:  
`bpftool cgroup attach /sys/fs/cgroup/user.slice/ egress pinned /sys/fs/bpf/cgroup_firewall multi`

Block an IP via update an item to the blocked_map with:  
`bpftool map update id 222 key 192 168 10 1  value 192 168 10 1`
note that, src ip or dst ip are used as key, so key equls to value.

Get connections:
`bpftool -j map pop name flows_map`

Debug:  
`bpftool prog tracelog`
