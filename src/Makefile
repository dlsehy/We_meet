BPF_CLANG = clang
BPFTOOL = bpftool
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_arm64 -Wall -Werror \
  -Wno-error=cpp -Wno-error=visibility \
  -I../include -I. -I/usr/include -I/usr/include/aarch64-linux-gnu

BPF_OBJ = procmon.bpf.o
SKEL_HDR = procmon.skel.h
LOADER_BIN = loader

all: $(LOADER_BIN)

$(BPF_OBJ): procmon.bpf.c
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

$(SKEL_HDR): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(LOADER_BIN): loader.c $(SKEL_HDR)
	gcc -g -O2 -Wall -I../include loader.c -o $@ -lbpf -lelf -lz

clean:
	rm -f *.o $(SKEL_HDR) $(LOADER_BIN)