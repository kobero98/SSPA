obj-m += the_usctm.o
the_usctm-objs += usctm.o ./lib/vtpmo.o

all:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules 
clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean
insmod:
	insmod the_usctm.ko
rmmod:
	rmmod the_usctm.ko
compile-extern:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Module/Linux_sys_call_table modules 
clean-extern:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD)/Module/Linux_sys_call_table clean
insmod-extern:
	insmod Module/Linux_sys_call_table/the_usctm.ko
rmmod-extern:
	rmmod -f the_usctm.ko