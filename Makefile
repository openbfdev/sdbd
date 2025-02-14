# SPDX-License-Identifier: GPL-2.0-or-later */
#
# Copyright(c) 2024 John Sanpe <sanpeqf@gmail.com>
#

SDBD_C_FLAGS = -Wall -Wextra -Wno-unused-parameter \
	-Wl,--gc-sections -ffunction-sections -fdata-sections \
	-lbfenv -lbfdev -lpthread -lutil

SDBD_C_DEBUG_FLAGS = $(SDBD_C_FLAGS) -g -DDEBUG \
	-fsanitize=address -fsanitize=undefined \
	-fsanitize-recover=all -fno-omit-frame-pointer \
	-fno-stack-protector

all: sdbd
debug: sdbd-debug
PHONY += all debug

clean:
	rm -rf sdbd sdbd-small sdbd-debug
PHONY += all

install: sdbd
	install -Dm755 sdbd /usr/local/bin/sdbd
PHONY += install

uninstall:
	rm -f /usr/local/bin/sdbd
PHONY += uninstall

sdbd: sdbd.c
	$(CROSS_COMPILE)gcc -o $@ $^ -O2 $(SDBD_C_FLAGS)
	$(CROSS_COMPILE)strip $@

sdbd-small: sdbd.c
	$(CROSS_COMPILE)gcc -o $@ $^ -O2 -DPROFILE_SMALL $(SDBD_C_FLAGS)
	$(CROSS_COMPILE)strip $@

sdbd-debug: sdbd.c
	$(CROSS_COMPILE)gcc -o $@ $^ -O0 $(SDBD_C_DEBUG_FLAGS)

# Declare the contents of the PHONY variable as phony.
.PHONY: $(PHONY)
