TARGET := g7
KERNELDIR := /lib/modules/$(shell uname -r)/build

DEBUG_CFLAGS := -DDEBUG

SRC_FILES := $(wildcard $(src)/src/*.c)
SRC_FILES += $(wildcard $(src)/src/$(TARGET)/*.c)
SRC_FILES := $(SRC_FILES:$(src)/%=%)

obj-m += $(TARGET).o
$(TARGET)-objs := $(SRC_FILES:%.c=%.o)

ccflags-y := -std=gnu99 -Wno-declaration-after-statement

all: build

debug: clean
	@make -C $(KERNELDIR) M=$(PWD) ccflags-y="$(ccflags-y) -DDEBUG" modules

release: clean build

build:
	@make -C $(KERNELDIR) M=$(PWD) modules

client:
	@cc -O2 -std=gnu99 -o ./rkctl ./src/rkctl/rkctl.c
	-@setfattr -n user.rootkit -v rootkit ./rkctl

clean_client:
	@rm -f ./rkctl

clean:
	@make -C $(KERNELDIR) M=$(PWD) clean

test: debug remove clear_dmesg install
	-@./check_pingpong.py /proc/g7rkp
	-@dmesg

.PHONY: install
install:
	-@insmod ./$(TARGET).ko

.PHONY: tags
tags:
	-@ctags -R .

.PHONY: remove
remove:
	-@rmmod $(TARGET)

.PHONY: clear_dmesg
clear_dmesg:
	@dmesg -c >/dev/null

.PHONY: dmesg
dmesg:
	@dmesg
