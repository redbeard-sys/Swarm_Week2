# Builds into /tmp/shim-xdp inside the device (/shared may be read-only-ish and
# is shared between devices).
OUT  ?= /tmp/shim-xdp
ARCH := $(shell uname -m)

all: $(OUT)/shim_router.bpf.o $(OUT)/shimctl

$(OUT):
	mkdir -p $(OUT)

$(OUT)/shim_router.bpf.o: shim_router.bpf.c shim.h | $(OUT)
	clang -O2 -g -Wall -target bpf -I/usr/include/$(ARCH)-linux-gnu -c $< -o $@

$(OUT)/shimctl: shimctl.c shim.h | $(OUT)
	gcc -O2 -Wall -o $@ $< -lbpf -lelf -lz

clean:
	rm -rf $(OUT)

.PHONY: all clean
