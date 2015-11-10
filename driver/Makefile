#CFLAGS = -DMODVERSIONS
EXTRA_CFLAGS = -Wall -DDEBUG
ifneq ($(KERNELRELEASE),)

#kbuild syntax. dependency relationshsip of files and target modules are listed here.

obj-m := zcopy_rw.o
#obj-m += e1000/
zcopy_rw-objs := zero_copy_rw.o

else

PWD  := $(shell pwd)
KVER ?= $(shell uname -r)
KDIR := /lib/modules/$(KVER)/build
	
all:
	$(MAKE) -C $(KDIR) M=$(PWD)
clean:
	rm -rf .*.cmd *.o *.mod.c *.ko .tmp_versions *.symvers modules.order *.unsigned
#	$(MAKE) -C e1000 clean
endif

