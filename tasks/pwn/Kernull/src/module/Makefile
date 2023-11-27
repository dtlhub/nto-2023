obj-m := vuln.o
KBUILD_DIR := /home/synerr/Trash/build/
CFLAGS_vuln.o := -O0 -g

all:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) modules

clean:
	$(MAKE) -C $(KBUILD_DIR) M=$(shell pwd) clean
