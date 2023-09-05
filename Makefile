obj-m += ptyhook.o

ptyhook: ptyhook.c
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) modules

clean:
	make -C /lib/modules/$(shell uname -r)/build M=$(PWD) clean

insmod: ptyhook
	sudo insmod ptyhook.ko

rmmod:
	sudo rmmod ptyhook
