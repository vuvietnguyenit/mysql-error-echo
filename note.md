command line flag:

mysql-error-echo run --port 3306 -v

-> -verbose log in root cmd


# Dependencies need to installed first

# Debugging

Try to load ebpf program by **bpftool** first:

```sh
bpftool prog loadall app/internal/ebpf/mysqltrace_bpfel_gobpf.o /sys/fs/bpf/
```
Check program load successful
-> Then can get id of program by name:

```sh
bpftool prog show
```

Attach program to an interface

```sh
# we need to use xdpgeneric because my VM didn't support legacy xdp
bpftool net attach xdpgeneric id 187 dev ens3
```

Detach program to by interface

```sh
# we need to use xdpgeneric because my VM didn't support legacy xdp
bpftool net detach xdpgeneric dev ens3
```

Pin map
```sh
sudo mkdir -p /sys/fs/bpf/xdp_maps
sudo bpftool map pin name events /sys/fs/bpf/xdp_maps/events

```