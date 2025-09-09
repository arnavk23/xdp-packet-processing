all: xdp_prog.o user_forwarder

xdp_prog.o: xdp_prog.c
	clang -O2 -target bpf \
		-I/usr/src/linux-source/include \
		-I/usr/src/linux-source/arch/x86/include \
		-I/usr/src/linux-source/arch/x86/include/generated \
		-I/usr/src/linux-source/arch/x86/include/generated/uapi \
		-I/usr/src/linux-source/include/uapi \
		-I/usr/src/linux-source/include/generated/uapi \
		-c xdp_prog.c -o xdp_prog.o

user_forwarder: user_forwarder.c
	gcc -o user_forwarder user_forwarder.c -lbpf

clean:
	rm -f xdp_prog.o user_forwarder
