CC := gcc
CLANG := clang
BPFTOOL := bpftool
BUILD := build
ARCH_INCLUDE := /usr/include/$(shell uname -m)-linux-gnu

.PHONY: all clean
all: $(BUILD)/mmap_guard $(BUILD)/mmap_test $(BUILD)/benchmark_mmap

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/vmlinux.h: | $(BUILD)
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

$(BUILD)/mmap_guard.bpf.o: src/mmap_guard.bpf.c include/common.h $(BUILD)/vmlinux.h
	$(CLANG) -O2 -g -Wall -Wextra -target bpf -D__TARGET_ARCH_x86 -I$(BUILD) -Iinclude -I$(ARCH_INCLUDE) -c $< -o $@

$(BUILD)/mmap_guard: src/mmap_guard.c include/common.h $(BUILD)/mmap_guard.bpf.o
	$(CC) -O2 -g -Wall -Wextra -Werror -Iinclude $< -o $@ $$(pkg-config --cflags --libs libbpf) -lelf -lz

$(BUILD)/mmap_test: tests/mmap_test.c | $(BUILD)
	$(CC) -O2 -g -Wall -Wextra -Werror $< -o $@

$(BUILD)/benchmark_mmap: tests/benchmark_mmap.c | $(BUILD)
	$(CC) -std=c11 -O2 -g -Wall -Wextra -Werror $< -o $@

clean:
	rm -rf $(BUILD)
