#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0-or-later
#
# Copyright (c) 2025, Zhenlin Wang <zhenlin.wang@openbfdev.com>
# Copyright (c) 2026, Openbfdev Organization
# All rights reserved.
#

. /etc/profile
export SHELL="/bin/bash"
export TERM="xterm-256color"
cd /root

USB_ATTRIBUTE=0x409
USB_GROUP=openbfdev
USB_SKELETON=b.1

CONFIGFS_DIR=/sys/kernel/config
USB_CONFIGFS_DIR=${CONFIGFS_DIR}/usb_gadget/${USB_GROUP}
USB_STRINGS_DIR=${USB_CONFIGFS_DIR}/strings/${USB_ATTRIBUTE}
USB_FUNCTIONS_DIR=${USB_CONFIGFS_DIR}/functions
USB_CONFIGS_DIR=${USB_CONFIGFS_DIR}/configs/${USB_SKELETON}
USB_FUNCTIONS_CNT=1

configfs_init() {
	mkdir -p /dev/usb-ffs
	mount -t configfs none ${CONFIGFS_DIR}

	mkdir -p ${USB_CONFIGFS_DIR} -m 0770
	echo 0x1d6b > ${USB_CONFIGFS_DIR}/idVendor
	echo 0x0104 > ${USB_CONFIGFS_DIR}/idProduct
	echo 0x0310 > ${USB_CONFIGFS_DIR}/bcdDevice
	echo 0x0200 > ${USB_CONFIGFS_DIR}/bcdUSB

	mkdir -p ${USB_STRINGS_DIR} -m 0770
	echo "openbfdev" > ${USB_STRINGS_DIR}/manufacturer
	echo "sdbd" > ${USB_STRINGS_DIR}/product

	SERIAL=$(cat /proc/cpuinfo | grep Serial | awk '{print $3}')
	if [ -z $SERIAL ]; then
		SERIAL=0123456789ABCDEF
	fi
	echo $SERIAL >${USB_STRINGS_DIR}/serialnumber

	mkdir -p ${USB_CONFIGS_DIR} -m 0770
	mkdir -p ${USB_CONFIGS_DIR}/strings/${USB_ATTRIBUTE} -m 0770

	mkdir -p ${USB_FUNCTIONS_DIR}/ffs.adb
	echo 0x1 > ${USB_CONFIGFS_DIR}/os_desc/b_vendor_code
	echo "MSFT100" > ${USB_CONFIGFS_DIR}/os_desc/qw_sign
	echo 500 > ${USB_CONFIGS_DIR}/MaxPower
	ln -s ${USB_CONFIGS_DIR} ${USB_CONFIGFS_DIR}/os_desc/b.1
}

syslink_function() {
	ln -s ${USB_FUNCTIONS_DIR}/$1 ${USB_CONFIGS_DIR}/f${USB_FUNCTIONS_CNT}
	let USB_FUNCTIONS_CNT=USB_FUNCTIONS_CNT+1
}

modprobe gadgetfs
modprobe libcomposite

# initialize usb configfs
test -d ${USB_CONFIGFS_DIR} || configfs_init

# adbd function
if [ -f /usr/bin/sdbd ]; then
	syslink_function ffs.adb
	mkdir /dev/usb-ffs/adb -m 0770
	mount -o uid=1000,gid=1000 -t functionfs adb /dev/usb-ffs/adb
	sdbd -dsp /run/sdbd.pid
fi

# start usb gadget
UDC=$(ls /sys/class/udc/ | awk '{print $1}')

cat << EOF > /run/usbd.sh
#!/usr/bin/env bash
echo -1000 >/proc/\$\$/oom_score_adj
exec 3>/dev/watchdog
while true; do
	echo 'S' >&3
	if [ "#\$(cat ${USB_CONFIGFS_DIR}/UDC)" == "#$UDC" ]; then
		sleep 1
		continue
	fi
	if [ -f /usr/bin/sdbd ]; then
		if [ "#\$(cat /proc/\$(cat /run/sdbd.pid)/comm)" != "#sdbd" ]; then
			sdbd -dsp /run/sdbd.pid
		fi
	fi
	echo $UDC > ${USB_CONFIGFS_DIR}/UDC
	sleep 0.2
done
EOF

chmod +x /run/usbd.sh
nohup /run/usbd.sh >/dev/null 2>&1 &
