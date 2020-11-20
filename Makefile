TARGET := g7
KERNELDIR := /lib/modules/$(shell uname -r)/build

src_files := $(wildcard $(src)/src/*.c)
src_files += $(wildcard $(src)/src/$(TARGET)/*.c)
src_files := $(src_files:$(src)/%=%)

obj-m += $(TARGET).o
$(TARGET)-objs := $(src_files:%.c=%.o)

all:
	make -C $(KERNELDIR) M=$(PWD) modules

clean:
	make -C $(KERNELDIR) M=$(PWD) clean

install:
	sudo insmod ./$(TARGET).ko

remove:
	sudo rmmod $(TARGET)
