CLANG?=clang
CFLAGS:=-O2 -g -Wall

build: generate
	go build -o counter .

generate: export BPF_CLANG:=$(CLANG)
generate: export BPF_CFLAGS:=$(CFLAGS)
generate:
	go generate syn_counter.go