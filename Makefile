#KERNELDIR := /home/tong/android-kernel/goldfish
KERNELDIR := /home/tong/GT-I9070_GB_Opensource/GT-I9070_Kernel
PWD := $(shell pwd)
ARCH=arm
CROSS_COMPILE=/home/tong/android-toolchain/prebuilt/linux-x86/toolchain/arm-eabi-4.4.3/bin/arm-eabi-
CC=$(CROSS_COMPILE)gcc
LD=$(CROSS_COMPILE)ld
obj-m := net_hook_module.o
modules:
	$(MAKE) -C $(KERNELDIR) ARCH=$(ARCH) CROSS_COMPILE=$(CROSS_COMPILE) M=$(PWD) modules
