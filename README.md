# xdp-SYN-flood-defender
A simple defender using eBPF XDP
Reference:
- [Hello World eBPF program](https://github.com/ns1/xdp-workshop)
- [cilium/ebpf XDP example](https://github.com/cilium/ebpf/tree/master/examples/xdp)

## Environment
```
sudo apt-get update
sudo apt-get install -y make clang llvm libelf-dev libbpf-dev bpfcc-tools libbpfcc-dev
v beta
```

## SYN counter using XDP
```
cd syn_counter
make
go run syn_counter.go
or
./counter
```

## SYN flood defender using XDP
```
cd syn_flood_defender
make
go run syn_flood_defender.go
or
./defender
```