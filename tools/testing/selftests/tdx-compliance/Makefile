# SPDX-License-Identifier: GPL-2.0-only

CFLAGS += -O3 -Wl,-no-as-needed -Wall $(KHDR_INCLUDES) -static

TEST_GEN_PROGS := tdx_guest_test

TDX_TESTMOD_DIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
KDIR ?= $(abspath $(TDX_TESTMOD_DIR)/../../../..)

MODULES = tdx-compliance.ko

obj-m += tdx-compliance.o

all:
	@make -C $(KDIR) M=$(TDX_TESTMOD_DIR) modules

clean:
	@make -C $(KDIR) M=$(TDX_TESTMOD_DIR) clean
