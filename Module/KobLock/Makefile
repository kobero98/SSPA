obj-m := the_koblock.o
the_koblock-objs += bitmask.o koblock.o
KDIR := /lib/modules/$(shell uname -r)/build
# CFLAGS += -msoft-float -msse -msse2 -msse3 -msse4
# systemcalltable:=$(shell cat /sys/module/the_usctm/parameters/sys_call_table_address)
# array_free_entries:=$(shell cat /sys/module/the_usctm/parameters/free_entries) 
EXTRA_CFLAGS:= -g -msoft-float -D FIRST -D DEBUG
all:
	make -C $(KDIR) M=$(PWD) modules
clean:
	make -C $(KDIR) M=$(PWD) clean 
insmod:
	insmod  the_koblock.ko systemcall_table=$(shell cat /sys/module/the_usctm/parameters/sys_call_table_address) free_entries=$(shell cat /sys/module/the_usctm/parameters/free_entries) 
rmmod:
	rmmod -f the_koblock.ko
compile-extern:
	make -C $(KDIR) M=$(PWD)/Module/KobLock modules
insmod-extern:
	insmod  Module/KobLock/the_koblock.ko systemcall_table=$(shell cat /sys/module/the_usctm/parameters/sys_call_table_address) free_entries=$(shell cat /sys/module/the_usctm/parameters/free_entries) 
rmmod-extern:
	rmmod -f the_koblock.ko
clean-extern:
	make -C $(KDIR) M=$(PWD)/Module/KobLock clean
