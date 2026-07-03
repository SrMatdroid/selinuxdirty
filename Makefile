KPATCH_DIR := kpatch
CC := aarch64-linux-gnu-gcc
CFLAGS := -O2 -fno-asynchronous-unwind-tables -fno-unwind-tables -D__user=
INC := -I$(KPATCH_DIR)/kernel -I$(KPATCH_DIR)/kernel/include -I$(KPATCH_DIR)/kernel/patch/include -I$(KPATCH_DIR)/kernel/linux/include -I$(KPATCH_DIR)/kernel/linux/arch/arm64/include -I$(KPATCH_DIR)/kernel/linux/tools/arch/arm64/include
OUT := out

SRCS := selinux_execmem_hide.c
OBJS := $(SRCS:.c=.o)
TARGET := $(OUT)/selinux_execmem_hide.kpm

.PHONY: all clean distclean sdk

all: $(TARGET)

$(KPATCH_DIR)/kernel:
	git clone --depth 1 https://github.com/KernelSU-Next/KPatch-Next $(KPATCH_DIR)

sdk: $(KPATCH_DIR)/kernel

$(OBJS): %.o: %.c sdk
	$(CC) $(CFLAGS) $(INC) -c -o $@ $<

$(TARGET): $(OBJS) | $(OUT)
	$(CC) -r -o $@ $^

$(OUT):
	mkdir -p $(OUT)

clean:
	rm -f $(OBJS)
	rm -rf $(OUT)

distclean: clean
	rm -rf $(KPATCH_DIR)
