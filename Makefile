TARGET := g7
KERNELDIR := /lib/modules/$(shell uname -r)/build

DEBUG_CFLAGS := -DDEBUG

SRC_FILES := $(wildcard $(src)/src/*.c)
SRC_FILES += $(wildcard $(src)/src/$(TARGET)/*.c)
SRC_FILES := $(SRC_FILES:$(src)/%=%)

obj-m += $(TARGET).o
$(TARGET)-objs := $(SRC_FILES:%.c=%.o)

ccflags-y := -std=std99 -Wno-declaration-after-statement

all: test

debug: clean
	@make -C $(KERNELDIR) M=$(PWD) ccflags-y="-DDEBUG" modules

release: clean build

build:
	@make -C $(KERNELDIR) M=$(PWD) modules

clean:
	@make -C $(KERNELDIR) M=$(PWD) clean

test: debug remove clear_dmesg install
	-@sudo ./check_pingpong.py /proc/g7rkp
	-@dmesg

.PHONY: install
install:
	-@sudo insmod ./$(TARGET).ko

.PHONY: remove
remove:
	-@sudo rmmod $(TARGET)

.PHONY: clear_dmesg
clear_dmesg:
	@sudo dmesg -c >/dev/null

.PHONY: dmesg
dmesg:
	@dmesg
