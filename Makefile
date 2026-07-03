KERNELDIR ?= kernel-headers
obj-m += selinux_execmem_hide.o
ccflags-y := -D__KERNEL__ -DMODULE

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

.PHONY: all clean
