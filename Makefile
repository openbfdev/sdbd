# SPDX-License-Identifier: GPL-2.0-or-later */
#
# Copyright(c) 2024 sanpeqf <sanpeqf@gmail.com>
#

SDBD_C_FLAGS = -Wall -Wextra -Wno-unused-parameter \
	-ffunction-sections -fdata-sections -Wl,--gc-sections \
	-Wl,--whole-archive -Wl,-Bstatic -lbfenv -lbfdev \
	-Wl,--no-whole-archive -Wl,-Bdynamic -lpthread -lutil

all: sdbd sdbd-debug
PHONY += all

clean:
	rm -rf sdbd sdbd-debug
PHONY += all

sdbd: sdbd.c
	gcc -o $@ $^ -O2 $(SDBD_C_FLAGS)
	strip $@

sdbd-debug: sdbd.c
	gcc -o $@ $^ -g -O0 -DDEBUG $(SDBD_C_FLAGS)

# Declare the contents of the PHONY variable as phony.
.PHONY: $(PHONY)
