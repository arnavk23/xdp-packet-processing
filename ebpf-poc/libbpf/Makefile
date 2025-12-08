BPF_CLANG ?= clang
BPF_CLANG_PLUS ?= clang++
BPF_CFLAGS ?= -O2 -g -Wall -target bpf

all: recv_count.bpf.o recv_count

recv_count.bpf.o: recv_count.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

recv_count: recv_count.c recv_count.bpf.o
	$(BPF_CLANG_PLUS) -g -O2 -o $@ recv_count.c -lbpf

clean:
	rm -f recv_count recv_count.bpf.o
