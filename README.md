# xdp-SYN-flood-defender
A simple ddos defender using eBPF and cilium/eBPF library.
- a SYN counter: use eBPF map to count number of packets of each IPs
- SYN flood defender: explore one more step to block hosts that send SYN packets too fast

## Environment
```
sudo apt-get update
sudo apt-get install -y make clang llvm libelf-dev libbpf-dev bpfcc-tools libbpfcc-dev
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
cd ../attack
pip install scapy
python syn_flood.py
```

## Reference:
- [Hello World eBPF program](https://github.com/ns1/xdp-workshop)
- [cilium/ebpf XDP example](https://github.com/cilium/ebpf/tree/master/examples/xdp)