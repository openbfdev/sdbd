# SPDX-License-Identifier: GPL-2.0-or-later */
#
# Copyright(c) 2025 John Sanpe <sanpeqf@gmail.com>
#

all: sdbd
PHONY += all

clean:
	rm -rf sdbd sdbd-debug
PHONY += all

sdbd: sdbd-debug
	strip -o $@ $^

sdbd-debug: sdbd.c
	gcc -o $@ $^ -O2 -Wall -Wextra -Wno-unused-parameter \
		-ffunction-sections -fdata-sections -Wl,--gc-sections \
		-Wl,--whole-archive -Wl,-Bstatic -lbfenv -lbfdev \
		-Wl,--no-whole-archive -Wl,-Bdynamic -lpthread -lutil

# Declare the contents of the PHONY variable as phony.
.PHONY: $(PHONY)
