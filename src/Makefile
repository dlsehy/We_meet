BPF_CLANG = clang
BPFTOOL = bpftool
BPF_CFLAGS = -g -O2 -target bpf -D__TARGET_ARCH_arm64 -Wall -Werror \
  -Wno-error=cpp -Wno-error=visibility \
  -I../include -I. -I/usr/include -I/usr/include/aarch64-linux-gnu

BPF_OBJ = procmon.bpf.o
SKEL_HDR = procmon.skel.h
LOADER_BIN = loader

.PHONY: all clean

all: $(LOADER_BIN)

# 1. BPF 오브젝트 파일 생성
$(BPF_OBJ): procmon.bpf.c event.h
	$(BPF_CLANG) $(BPF_CFLAGS) -c $< -o $@

# 2. 스켈레톤 헤더 생성
$(SKEL_HDR): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

# 3. 로더 바이너리 빌드
$(LOADER_BIN): loader.c $(SKEL_HDR) event.h
	gcc -g -O2 -Wall -I../include loader.c -o $@ -lbpf -lelf -lz

# 4. 정리
clean:
	rm -f *.o $(SKEL_HDR) $(LOADER_BIN)