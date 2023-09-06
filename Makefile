obj-m += ptyhook.o

modules:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insmod: modules
	sudo insmod ptyhook.ko

rmmod:
	sudo rmmod ptyhook
