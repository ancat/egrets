LINUX_HEADERS=$(shell rpm -ql kernel-devel | head -1)
CFLAGS=$(CFLAGS)

all:
	clang $(CFLAGS) -D__KERNEL__ -D__ASM_SYSREG_H \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wunused \
		-Wall \
		-Werror \
        -I $(LINUX_HEADERS)/include/linux \
        -I $(LINUX_HEADERS)/arch/x86/include \
        -I $(LINUX_HEADERS)/arch/x86/include/generated \
        -I $(LINUX_HEADERS)/include \
        -I $(LINUX_HEADERS)/include/generated/uapi \
        -I $(LINUX_HEADERS)/arch/x86/include/uapi \
        -I $(LINUX_HEADERS)/include/uapi \
		-O2 -emit-llvm -c /dist/rdns.c \
		-o - | llc -march=bpf -filetype=obj -o "/dist/rdns.o"
