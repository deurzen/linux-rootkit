obj-m += g7.o
g7-objs := ./src/g7.o ./src/ioctl.o

KERNELDIR := /lib/modules/$(shell uname -r)/build

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean
