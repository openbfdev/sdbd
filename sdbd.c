/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2025 John Sanpe <sanpeqf@gmail.com>
 */

#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <err.h>
#include <pwd.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <inttypes.h>
#include <dirent.h>
#include <utime.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#define MODULE_NAME "sdbd"
#define bfdev_log_fmt(fmt) MODULE_NAME ": " fmt

#define SDBD_VERSION "v0.3"
#define SDBD_INFO MODULE_NAME "/" SDBD_VERSION

#ifndef DEBUG
# define BFDEV_LOGLEVEL_MAX BFDEV_LEVEL_NOTICE
#endif

#include <bfdev.h>
#include <bfenv.h>

#define USB_FFS_ADB_PATH "/dev/usb-ffs/adb/"
#define USB_FFS_ADB_EP(x) USB_FFS_ADB_PATH#x
#define USB_FFS_ADB_CTL USB_FFS_ADB_EP(ep0)
#define USB_FFS_ADB_OUT USB_FFS_ADB_EP(ep1)
#define USB_FFS_ADB_IN USB_FFS_ADB_EP(ep2)

/* USB Descriptor */
#define ADB_SUBCLASS 0x42
#define ADB_PROTOCOL 0x1
#define ADB_INTERFACE "ADB Interface"
#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512
#define MAX_PACKET_SIZE_SS 1024

/* ADB Version */
#define ADB_VERSION 0x1000000
#define ADB_DEVICE_BANNER "device"
#define MAX_PAYLOAD_V1 BFDEV_SZ_4KiB
#define MAX_PAYLOAD_V2 BFDEV_SZ_256KiB
#define SYNC_MAXNAME BFDEV_SZ_1KiB
#define SYNC_MAXDATA BFDEV_SZ_64KiB

#define RSANUMBYTES 256
#define RSANUMU32S (RSANUMBYTES / sizeof(uint32_t))

/* ADB Command */
#define PCMD_CNXN 0x4e584e43
#define PCMD_AUTH 0x48545541
#define PCMD_OPEN 0x4e45504f
#define PCMD_OKAY 0x59414b4f
#define PCMD_CLSE 0x45534c43
#define PCMD_WRTE 0x45545257

/* SYNC Service Command */
#define SYNC_CMD_STAT 0x54415453
#define SYNC_CMD_LIST 0x5453494c
#define SYNC_CMD_SEND 0x444e4553
#define SYNC_CMD_RECV 0x56434552
#define SYNC_CMD_DATA 0x41544144
#define SYNC_CMD_DENT 0x544e4544
#define SYNC_CMD_DONE 0x454e4f44
#define SYNC_CMD_OKAY 0x59414b4f
#define SYNC_CMD_FAIL 0x4c494146
#define SYNC_CMD_QUIT 0x54495551

#define AUTH_TOKEN 1
#define AUTH_SIGNATURE 2
#define AUTH_RSAPUBLICKEY 3
#define TOKEN_SIZE BFDEV_SHA1_DIGEST_SIZE

#define SHELL_FUTURE_V2 "v2"
#define SHELL_FUTURE_PTY "pty"
#define SHELL_FUTURE_RAW "raw"
#define SHELL_FUTURE_TERM "TERM="

#define SHELL_CMD_STDIN 0
#define SHELL_CMD_STDOUT 1
#define SHELL_CMD_STDERR 2
#define SHELL_CMD_EXIT 3
#define SHELL_CMD_CLOSE 4
#define SHELL_CMD_WINSIZE 5

/* SDBD Configuration */
#ifdef PROFILE_SMALL
# define USB_FIFO_DEPTH 4
# define MAX_PAYLOAD MAX_PAYLOAD_V1
#endif

#ifndef USB_FIFO_DEPTH
# define USB_FIFO_DEPTH 64
#endif

#ifndef MAX_PAYLOAD
# define MAX_PAYLOAD MAX_PAYLOAD_V2
#endif

#define SERVICE_TIMEOUT (12 * 60 * 60 * 1000)
#define ASYNC_IOWAIT_TIME 1000
#define AUTH_FAIL_DELAY 500

static bool sdbd_daemon;
static bool sdbd_auth;
static const char *sdbd_shell;
static const char *sdbd_auth_file;
static unsigned long sdbd_timeout = SERVICE_TIMEOUT;
static BFDEV_LIST_HEAD(sdbd_auth_keys);

static const char *
cnxn_props[] = {
    "ro.product.name",
    "ro.product.model",
    "ro.product.device",
    "features",
};

static const char *
cnxn_values[] = {
    "Linux",
    "Systemd",
    "GNU",
    "shell_v2,cmd",
};

static const char * const
auth_key_paths[] = {
    "/adb_keys",
    "/data/misc/adb/adb_keys",
};

struct rsa_publickey {
    bfdev_le32 len;
    bfdev_le32 n0inv;
    bfdev_le32 n[RSANUMU32S];
    bfdev_le32 rr[RSANUMU32S];
    bfdev_le32 exponent;
} __bfdev_packed;

struct adb_message {
    bfdev_le32 command;
    bfdev_le32 args[2];
    bfdev_le32 length;
    bfdev_le32 cksum;
    bfdev_le32 magic;
} __bfdev_packed;

struct shell_data {
    uint8_t id;
    bfdev_le32 size;
} __bfdev_packed;

struct sync_request {
    bfdev_le32 id;
    bfdev_le32 namelen;
} __bfdev_packed;

struct sync_stat {
    bfdev_le32 id;
    bfdev_le32 mode;
    bfdev_le32 size;
    bfdev_le32 time;
} __bfdev_packed;

struct sync_directry {
    bfdev_le32 id;
    bfdev_le32 mode;
    bfdev_le32 size;
    bfdev_le32 time;
    bfdev_le32 namelen;
} __bfdev_packed;

struct sync_data {
    bfdev_le32 id;
    bfdev_le32 size;
} __bfdev_packed;

struct sync_status {
    bfdev_le32 id;
    bfdev_le32 msglen;
} __bfdev_packed;

struct adb_functionfs_descs_head {
    bfdev_le32 magic;
    bfdev_le32 length;
    bfdev_le32 flags;
} __bfdev_packed;

struct adb_functionfs_strings_head {
    bfdev_le32 magic;
    bfdev_le32 length;
    bfdev_le32 str_count;
    bfdev_le32 lang_count;
} __bfdev_packed;

struct adb_endpoint_descriptor_no_audio {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bEndpointAddress;
    uint8_t bmAttributes;
    bfdev_le16 wMaxPacketSize;
    uint8_t bInterval;
} __bfdev_packed;

struct adb_ss_ep_comp_descriptor {
    uint8_t bLength;
    uint8_t bDescriptorType;
    uint8_t bMaxBurst;
    uint8_t bmAttributes;
    bfdev_le16 wBytesPerInterval;
} __bfdev_packed;

struct adb_os_desc_header {
    uint8_t interface;
    bfdev_le32 dwLength;
    bfdev_le16 bcdVersion;
    bfdev_le16 wIndex;
    union {
        struct {
            uint8_t bCount;
            uint8_t Reserved;
        };
        bfdev_le16 wCount;
    };
} __bfdev_packed;

static const struct {
    struct adb_functionfs_descs_head header;
    bfdev_le32 fs_count;
    bfdev_le32 hs_count;
    bfdev_le32 ss_count;
    bfdev_le32 os_count;
    struct {
        struct usb_interface_descriptor intf;
        struct adb_endpoint_descriptor_no_audio source;
        struct adb_endpoint_descriptor_no_audio sink;
    } __bfdev_packed fs_descs, hs_descs;
    struct {
        struct usb_interface_descriptor intf;
        struct adb_endpoint_descriptor_no_audio source;
        struct adb_ss_ep_comp_descriptor source_comp;
        struct adb_endpoint_descriptor_no_audio sink;
        struct adb_ss_ep_comp_descriptor sink_comp;
    } __bfdev_packed ss_descs;
    struct adb_os_desc_header os_header;
    struct usb_ext_compat_desc os_desc;
} __bfdev_packed adb_desc = {
    .header = {
        .magic = bfdev_cpu_to_le32(FUNCTIONFS_DESCRIPTORS_MAGIC_V2),
        .length = bfdev_cpu_to_le32(sizeof(adb_desc)),
        .flags = bfdev_cpu_to_le32(
            FUNCTIONFS_HAS_FS_DESC | FUNCTIONFS_HAS_HS_DESC |
            FUNCTIONFS_HAS_SS_DESC | FUNCTIONFS_HAS_MS_OS_DESC
        ),
    },
    .fs_count = bfdev_cpu_to_le32(3),
    .hs_count = bfdev_cpu_to_le32(3),
    .ss_count = bfdev_cpu_to_le32(5),
    .os_count = bfdev_cpu_to_le32(1),
    .fs_descs = {
        .intf = {
            .bLength = sizeof(adb_desc.fs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bAlternateSetting = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
            .bInterfaceSubClass = ADB_SUBCLASS,
            .bInterfaceProtocol = ADB_PROTOCOL,
            .iInterface = 1,
        },
        .source = {
            .bLength = sizeof(adb_desc.fs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = bfdev_cpu_to_le16(MAX_PACKET_SIZE_HS),
            .bInterval = 0,
        },
        .sink = {
            .bLength = sizeof(adb_desc.fs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = bfdev_cpu_to_le16(MAX_PACKET_SIZE_HS),
            .bInterval = 0,
        },
    },
    .hs_descs = {
        .intf = {
            .bLength = sizeof(adb_desc.hs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bAlternateSetting = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
            .bInterfaceSubClass = ADB_SUBCLASS,
            .bInterfaceProtocol = ADB_PROTOCOL,
            .iInterface = 1,
        },
        .source = {
            .bLength = sizeof(adb_desc.hs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = bfdev_cpu_to_le16(MAX_PACKET_SIZE_HS),
            .bInterval = 0,
        },
        .sink = {
            .bLength = sizeof(adb_desc.hs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = bfdev_cpu_to_le16(MAX_PACKET_SIZE_HS),
            .bInterval = 0,
        },
    },
    .ss_descs = {
        .intf = {
            .bLength = sizeof(adb_desc.ss_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = USB_CLASS_VENDOR_SPEC,
            .bInterfaceSubClass = ADB_SUBCLASS,
            .bInterfaceProtocol = ADB_PROTOCOL,
            .iInterface = 1,
        },
        .source = {
            .bLength = sizeof(adb_desc.ss_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = bfdev_cpu_to_le16(MAX_PACKET_SIZE_SS),
        },
        .source_comp = {
            .bLength = sizeof(adb_desc.ss_descs.source_comp),
            .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
            .bMaxBurst = 4,
        },
        .sink = {
            .bLength = sizeof(adb_desc.ss_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = bfdev_cpu_to_le16(MAX_PACKET_SIZE_SS),
        },
        .sink_comp = {
            .bLength = sizeof(adb_desc.ss_descs.sink_comp),
            .bDescriptorType = USB_DT_SS_ENDPOINT_COMP,
            .bMaxBurst = 4,
        },
    },
    .os_header = {
        .interface = 1,
        .dwLength = bfdev_cpu_to_le32(sizeof(adb_desc.os_header) +
            sizeof(adb_desc.os_desc)),
        .bcdVersion = bfdev_cpu_to_le16(1),
        .wIndex = bfdev_cpu_to_le16(4),
        .bCount = 1,
        .Reserved = 0,
    },
    .os_desc = {
        .bFirstInterfaceNumber = 0,
        .Reserved1 = 1,
        .CompatibleID = {0},
        .SubCompatibleID = {0},
        .Reserved2 = {0},
    },
};

static const struct {
    struct adb_functionfs_strings_head header;
    struct {
        bfdev_le16 code;
        const char str[sizeof(ADB_INTERFACE)];
    } __bfdev_packed lang;
} __bfdev_packed adb_str = {
    .header = {
        .magic = bfdev_cpu_to_le32(FUNCTIONFS_STRINGS_MAGIC),
        .length = bfdev_cpu_to_le32(sizeof(adb_str)),
        .str_count = bfdev_cpu_to_le32(1),
        .lang_count = bfdev_cpu_to_le32(1),
    },
    .lang = {
        .code = bfdev_cpu_to_le16(0x409),
        .str = ADB_INTERFACE,
    },
};

struct sdbd_packet {
    uint32_t command;
    uint32_t args[2];
    uint32_t length;
    uint32_t cksum;
    uint32_t magic;
};

struct sdbd_service {
    struct sdbd_ctx *sctx;
    bfenv_eproc_timer_t timer;
    bfdev_array_t stream;
    int (*write)(struct sdbd_service *service, void *data, size_t length);
    void (*close)(struct sdbd_service *service);

    uint32_t local;
    uint32_t remote;
};

struct sdbd_shell_service {
    struct sdbd_service service;
    bfenv_eproc_event_t event;
    pid_t pid;

    size_t inprogress;
    uint32_t cmd;
    uint32_t size;

    bool v2;
    char *term;
};

struct sdbd_sync_service {
    struct sdbd_service service;
    uint32_t cmd;
    uint32_t namelen;

    bfenv_eproc_event_t event;
    bfenv_iothread_t *fileio;
    int fd;

    size_t inprogress;
    size_t batch;
    char filename[SYNC_MAXNAME + 1];
    uint8_t buff[];
};

struct sdbd_ctx {
    bfenv_eproc_t *eproc;
    BFDEV_DECLARE_RADIX(services, struct sdbd_service *);
    bfenv_iothread_t *usbio_in;
    bfenv_iothread_t *usbio_out;

    bfdev_prandom_t rand;
    uint8_t token[TOKEN_SIZE];
    bool verified;

    uint32_t version;
    uint32_t max_payload;

    int fd_ctr;
    int fd_out;
    int fd_in;
    uint32_t sockid;

    bfenv_eproc_event_t usbev_in;
    bfenv_eproc_event_t usbev_out;
    bfenv_eproc_event_t sigev;

    struct adb_message msgbuff;
    uint32_t command;
    uint32_t args[2];
    uint32_t magic;
    uint32_t length;
    uint32_t check;
};

struct sdbd_rsa_publickey {
    bfdev_list_head_t list;
    uint32_t n[RSANUMU32S];
    uint32_t rr[RSANUMU32S];
    uint32_t len;
    uint32_t n0inv;
    uint32_t exponent;
};

static const uint8_t
kexpectedpad_sha_rsa2048[BFDEV_SHA1_DIGEST_SIZE] = {
    0xdc, 0xbd, 0xbe, 0x42, 0xd5, 0xf5, 0xa7, 0x2e,
    0x6e, 0xfc, 0xf5, 0x5d, 0xaf, 0x9d, 0xea, 0x68,
    0x7c, 0xfb, 0xf1, 0x67,
};

static const uint8_t
kexpectedpad_sha256_rsa2048[BFDEV_SHA256_DIGEST_SIZE] = {
    0xab, 0x28, 0x8d, 0x8a, 0xd7, 0xd9, 0x59, 0x92,
    0xba, 0xcc, 0xf8, 0x67, 0x20, 0xe1, 0x15, 0x2e,
    0x39, 0x8d, 0x80, 0x36, 0xd6, 0x6f, 0xf0, 0xfd,
    0x90, 0xe8, 0x7d, 0x8b, 0xe1, 0x7c, 0x87, 0x59,
};

static int
service_sync_write(struct sdbd_service *service, void *data, size_t length);

static ssize_t
path_read(const char *path, char *buff, size_t size)
{
    ssize_t length;
    int fd;

    fd = open(path, O_RDONLY);
    if (fd < 0) {
        bfdev_log_err("path read: failed to open file");
        return -BFDEV_EACCES;
    }

    length = read(fd, buff, size);
    if (length <= 0) {
        bfdev_log_err("path read: failed to open file");
        return -BFDEV_EFAULT;
    }

    close(fd);
    return length;
}

static int
sdbd_read(int fd, void *data, size_t size)
{
    size_t count;
    ssize_t rlen;

    count = 0;
    do {
        rlen = read(fd, data, size - count);
        if (rlen >= 0) {
            count += rlen;
            data += rlen;
            continue;
        }

        switch (errno) {
            case EINTR:
                break;

            case EAGAIN:
                bfdev_log_debug("sdbd read: iowaitting...\n");
                usleep(ASYNC_IOWAIT_TIME);
                break;

            default:
                bfdev_log_warn("sdbd read: error %d\n", errno);
                return -BFDEV_EIO;
        }
    } while (count < size);

    return -BFDEV_ENOERR;
}

static int
sdbd_write(int fd, const void *data, size_t size)
{
    size_t count;
    ssize_t rlen;

    count = 0;
    do {
        rlen = write(fd, data, size - count);
        if (rlen >= 0) {
            count += rlen;
            data += rlen;
            continue;
        }

        switch (errno) {
            case EINTR:
                break;

            case EAGAIN:
                bfdev_log_debug("sdbd write: iowaitting...\n");
                usleep(ASYNC_IOWAIT_TIME);
                break;

            default:
                bfdev_log_warn("sdbd write: error %d\n", errno);
                return -BFDEV_EIO;
        }
    } while (count < size);

    return -BFDEV_ENOERR;
}

static int
async_usb_enqueue(struct sdbd_ctx *sctx, const void *data, size_t size)
{
    int retval;

    for (;;) {
        retval = bfenv_iothread_write(sctx->usbio_in, sctx->fd_in, data, size);
        if (retval >= 0)
            break;

        switch (retval) {
            case -BFDEV_EAGAIN:
                bfdev_log_debug("async usb write: iowaitting...\n");\
                usleep(ASYNC_IOWAIT_TIME);
                break;

            default:
                bfdev_log_err("async usb write: error %d\n", errno);
                return -BFDEV_EIO;
        }
    }

    return -BFDEV_ENOERR;
}

static int
async_usb_write(struct sdbd_ctx *sctx, const void *data, size_t size)
{
    void *buff;
    int retval;

    buff = bfdev_malloc(NULL, size);
    if (!buff)
        return -BFDEV_ENOMEM;

    memcpy(buff, data, size);
    retval = async_usb_enqueue(sctx, buff, size);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
write_packet(struct sdbd_ctx *sctx, struct sdbd_packet *packet, void *payload)
{
    struct adb_message message;
    int retval;

    message.command = bfdev_cpu_to_le32(packet->command);
    message.args[0] = bfdev_cpu_to_le32(packet->args[0]);
    message.args[1] = bfdev_cpu_to_le32(packet->args[1]);
    message.length = bfdev_cpu_to_le32(packet->length);
    message.cksum = bfdev_cpu_to_le32(packet->cksum);
    message.magic = bfdev_cpu_to_le32(packet->magic);

    bfdev_log_debug("usbio write: message\n");
    retval = async_usb_write(sctx, &message, sizeof(message));
    if (retval < 0)
        return retval;

    if (packet->length) {
        BFDEV_BUG_ON(!payload);
        bfdev_log_debug("usbio write: payload\n");
        retval = async_usb_write(sctx, payload, packet->length);
        if (retval < 0)
            return retval;
    }

    return -BFDEV_ENOERR;
}

#if __ARM_NEON
# include <arm_neon.h>

static const char
hardware_accel[] = "Arm Neon";

static uint32_t
payload_cksum(uint8_t *payload, size_t length)
{
    uint32_t cksum;

    cksum = 0;
    while (length && !bfdev_align_ptr_check(payload, 16)) {
        cksum += *payload++;
        length--;
    }

    for (; length >= 16; length -= 16, payload += 16) {
        uint32x4_t data32;
        uint16x8_t data16;
        uint8x16_t data8;

        data8 = vld1q_u8(payload);
        data16 = vpaddlq_u8(data8);
        data32 = vpaddlq_u16(data16);

        cksum += vgetq_lane_u32(data32, 0) + vgetq_lane_u32(data32, 1) +
            vgetq_lane_u32(data32, 2) + vgetq_lane_u32(data32, 3);
    }

    while (length--)
        cksum += *payload++;

    return cksum;
}

#elif __SSE2__
# include <x86intrin.h>

static const char
hardware_accel[] = "Intel SSE2";

static uint32_t
payload_cksum(uint8_t *payload, size_t length)
{
    uint32_t cksum;
    __m128i sum;

    cksum = 0;
    while (length && !bfdev_align_ptr_check(payload, 16)) {
        cksum += *payload++;
        length--;
    }

    sum = _mm_setzero_si128();
    for (; length >= 16; length -= 16, payload += 16) {
        __m128i data;

        data = _mm_load_si128((const __m128i *)payload);
        sum = _mm_add_epi32(sum, _mm_sad_epu8(data, _mm_setzero_si128()));
    }

    sum = _mm_add_epi32(sum, _mm_srli_si128(sum, 8));
    cksum += _mm_cvtsi128_si32(sum);

    while (length--)
        cksum += *payload++;

    return cksum;
}

#else /* Generic */

static const char
hardware_accel[] = "None";

static uint32_t
payload_cksum(uint8_t *payload, size_t length)
{
    uint32_t cksum;

    cksum = 0;
    while (length-- > 0)
        cksum += *payload++;

    return cksum;
}

#endif

static void
key_subm(struct sdbd_rsa_publickey *key, uint32_t *var)
{
    unsigned int index;
    int64_t value;

    value = 0;
    for (index = 0; index < key->len; ++index) {
        value += (uint64_t)var[index] - key->n[index];
        var[index] = (uint32_t)value;
        value >>= 32;
    }
}

static int
key_gem(struct sdbd_rsa_publickey *key, uint32_t *var)
{
    unsigned int index;

    index = key->len;
    while (index--) {
        if (var[index] < key->n[index])
            return 0;
        if (var[index] > key->n[index])
            return 1;
    }

    return 1;
}

static void
mont_madd(struct sdbd_rsa_publickey *key,
          uint32_t *vc, uint32_t va, uint32_t *vb)
{
    unsigned int index;
    uint64_t keya, keyb;
    uint32_t data;

    keya = (uint64_t)va * vb[0] + vc[0];
    data = (uint32_t)keya * key->n0inv;
    keyb = (uint64_t)data * key->n[0] + (uint32_t)keya;

    for (index = 1; index < key->len; ++index) {
        keya = (keya >> 32) + (uint64_t)va * vb[index] + vc[index];
        keyb = (keyb >> 32) + (uint64_t)data * key->n[index] + (uint32_t)keya;
        vc[index - 1] = (uint32_t)keyb;
    }

    keya = (keya >> 32) + (keyb >> 32);
    vc[index - 1] = (uint32_t)keya;

    if (keya >> 32)
        key_subm(key, vc);
}

static void
mont_mul(struct sdbd_rsa_publickey *key,
         uint32_t *vc, uint32_t *va, uint32_t *vb)
{
    unsigned int index;

    memset(vc, 0, sizeof(*vc) * key->len);
    for (index = 0; index < key->len; ++index)
        mont_madd(key, vc, va[index], vb);
}

static void
mont_modpow(struct sdbd_rsa_publickey *key, uint8_t *inout)
{
    uint32_t buf1[RSANUMU32S], buf2[RSANUMU32S], buf3[RSANUMU32S];
    uint32_t *result, value;
    unsigned int index;

    for (index = 0; index < key->len; ++index) {
        value =
            ((uint32_t)inout[(key->len - 1 - index) * 4 + 0] << 24) |
            ((uint32_t)inout[(key->len - 1 - index) * 4 + 1] << 16) |
            ((uint32_t)inout[(key->len - 1 - index) * 4 + 2] << 8) |
            ((uint32_t)inout[(key->len - 1 - index) * 4 + 3] << 0);
        buf1[index] = value;
    }

    if (key->exponent == 65537) {
        result = buf3;
        mont_mul(key, buf2, buf1, key->rr);
        for (index = 0; index < 16; index += 2) {
            mont_mul(key, buf3, buf2, buf2);
            mont_mul(key, buf2, buf3, buf3);
        }
        mont_mul(key, result, buf2, buf1);
    } else if (key->exponent == 3) {
        result = buf2;
        mont_mul(key, buf2, buf1, key->rr);
        mont_mul(key, buf3, buf2, buf2);
        mont_mul(key, result, buf3, buf1);
    }

    if (key_gem(key, result))
        key_subm(key, result);

    for (index = 0; index < key->len; ++index) {
        value = result[key->len - 1 - index];
        inout[index * 4 + 0] = value >> 24;
        inout[index * 4 + 1] = value >> 16;
        inout[index * 4 + 2] = value >> 8;
        inout[index * 4 + 3] = value >> 0;
    }
}

static int
rsa_verify(struct sdbd_rsa_publickey *key, void *sig,
           uint8_t *hash, size_t hashlen)
{
    uint8_t buff[RSANUMBYTES];
    const uint8_t *padding_hash;
    unsigned int count;

    BFDEV_BUG_ON(key->len != RSANUMU32S);
    BFDEV_BUG_ON(key->exponent != 3 && key->exponent != 65537);

    if (hashlen != BFDEV_SHA1_DIGEST_SIZE &&
        hashlen != BFDEV_SHA256_DIGEST_SIZE) {
        bfdev_log_err("rsa verify: unsupported hash\n");
        return false;
    }

    memcpy(buff, sig, RSANUMBYTES);
    mont_modpow(key, (void *)buff);

    for (count = RSANUMBYTES - hashlen; count < RSANUMBYTES; ++count)
        buff[count] ^= *hash++;

    switch (hashlen) {
        case BFDEV_SHA1_DIGEST_SIZE: {
            bfdev_sha1_ctx_t sha1;
            padding_hash = kexpectedpad_sha_rsa2048;
            bfdev_sha1_init(&sha1);
            bfdev_sha1_update(&sha1, buff, RSANUMBYTES);
            bfdev_sha1_finish(&sha1, buff);
            break;
        }

        case BFDEV_SHA256_DIGEST_SIZE: {
            bfdev_sha2_ctx_t sha2;
            padding_hash = kexpectedpad_sha256_rsa2048;
            bfdev_sha256_init(&sha2);
            bfdev_sha2_update(&sha2, buff, RSANUMBYTES);
            bfdev_sha256_finish(&sha2, buff);
            break;
        }

        default:
            BFDEV_BUG();
    }

    if (memcmp(padding_hash, buff, hashlen)) {
        bfdev_log_notice("rsa verify: hash verify failed\n");
        return false;
    }

    return true;
}

static int
auth_verify(struct sdbd_ctx *sctx, void *sig, int siglen)
{
    struct sdbd_rsa_publickey *key;
    int retval;

    if (siglen != RSANUMBYTES) {
        bfdev_log_notice("auth verify: invalid input length\n");
        return false;
    }

    bfdev_list_for_each_entry(key, &sdbd_auth_keys, list) {
        retval = rsa_verify(key, sig, sctx->token, TOKEN_SIZE);
        if (retval < 0 || retval == true)
            return retval;
    }

    return false;
}

static int
send_packet(struct sdbd_ctx *sctx, struct sdbd_packet *packet, void *payload)
{
    uint32_t cksum, magic;

    BFDEV_BUG_ON(packet->length && !payload);
    cksum = payload_cksum(payload, packet->length);
    magic = ~packet->command;

    packet->cksum = cksum;
    packet->magic = magic;

    return write_packet(sctx, packet, payload);
}

static int
send_close(struct sdbd_ctx *sctx, uint32_t local, uint32_t remote)
{
    struct sdbd_packet packet;
    int retval;

    packet.command = PCMD_CLSE;
    packet.args[0] = local;
    packet.args[1] = remote;
    packet.length = 0;

    bfdev_log_info("send close: local %u remote %u\n", local, remote);
    retval = send_packet(sctx, &packet, NULL);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
send_okay(struct sdbd_ctx *sctx, uint32_t local, uint32_t remote)
{
    struct sdbd_packet packet;
    int retval;

    packet.command = PCMD_OKAY;
    packet.args[0] = local;
    packet.args[1] = remote;
    packet.length = 0;

    bfdev_log_info("send okay: local %u remote %u\n", local, remote);
    retval = send_packet(sctx, &packet, NULL);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
send_data(struct sdbd_ctx *sctx, uint32_t local, uint32_t remote,
          void *data, size_t size)
{
    struct sdbd_packet packet;
    int retval;

    packet.command = PCMD_WRTE;
    packet.args[0] = local;
    packet.args[1] = remote;
    packet.length = size;

    bfdev_log_debug("send data: local %u remote %u size %zu\n",
        local, remote, size);
    retval = send_packet(sctx, &packet, data);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
send_datas(struct sdbd_ctx *sctx, uint32_t local, uint32_t remote,
           void *data, size_t size)
{
    size_t xfer;
    int retval;

    bfdev_log_debug("send datas: local %u remote %u size %zu\n",
        local, remote, size);
    for (; (xfer = bfdev_min(size, sctx->max_payload)); size -= xfer) {
        retval = send_data(sctx, local, remote, data, xfer);
        if (retval < 0)
            return retval;
        data += xfer;
    }

    return -BFDEV_ENOERR;
}

static int
stream_append(struct sdbd_service *service, void *data, size_t size)
{
    void *buff;

    buff = bfdev_array_push(&service->stream, size);
    if (!buff)
        return -BFDEV_ENOMEM;
    memcpy(buff, data, size);

    return -BFDEV_ENOERR;
}

static ssize_t
stream_accumulate(struct sdbd_service *service, size_t request,
                  void *data, size_t append)
{
    size_t alreary, remain, avail;
    int retval;

    alreary = bfdev_array_size(&service->stream);
    BFDEV_BUG_ON(alreary > request);

    remain = request - alreary;
    avail = bfdev_min(remain, append);

    retval = stream_append(service, data, append);
    if (retval < 0)
        return retval;

    if (append < remain)
        return -BFDEV_EAGAIN;

    return avail;
}

static size_t
make_connect_data(char *buff, size_t bsize)
{
    size_t remaining, len;
    unsigned int count;

    remaining = bsize;
    len = bfdev_scnprintf(buff, remaining, "%s::", ADB_DEVICE_BANNER);
    remaining -= len;
    buff += len;

    for(count = 0; count < BFDEV_ARRAY_SIZE(cnxn_props); ++count) {
        len = bfdev_scnprintf(buff, remaining, "%s=%s;",
            cnxn_props[count], cnxn_values[count]);
        remaining -= len;
        buff += len;
    }

    return bsize - remaining + 1;
}

static int
send_connect(struct sdbd_ctx *sctx)
{
    uint8_t payload[MAX_PAYLOAD];
    struct sdbd_packet packet;
    size_t length;
    int retval;

    packet.command = PCMD_CNXN;
    packet.args[0] = sctx->version;
    packet.args[1] = sctx->max_payload;

    length = make_connect_data((char *)payload, sizeof(payload));
    if (length > MAX_PAYLOAD_V1)
        bfdev_log_warn("send connect: banner too large\n");

    bfdev_log_info("send connect: '%s'\n", payload);
    packet.length = length;

    retval = send_packet(sctx, &packet, payload);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
send_auth_request(struct sdbd_ctx *sctx)
{
    struct sdbd_packet packet;
    unsigned int count;
    int retval;

    packet.command = PCMD_AUTH;
    packet.args[0] = AUTH_TOKEN;
    packet.args[1] = 0;

    for (count = 0; count < TOKEN_SIZE; ++count)
        sctx->token[count] = bfdev_prandom_value(&sctx->rand);

    bfdev_log_info("send auth request\n");
    packet.length = TOKEN_SIZE;

    retval = send_packet(sctx, &packet, sctx->token);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static void
iothread_release(bfenv_iothread_request_t *request, void *pdata)
{
    free(request->buffer);
}

static pid_t
spawn_shell(struct sdbd_shell_service *shell, int *amaster,
            const char *path, char *cmdline)
{
    char ptsname[PATH_MAX], hostname[HOST_NAME_MAX];
    struct passwd *pwd;
    int child, fd, maxfd;
    int retval;
    pid_t pid;
    char *value;

    pid = forkpty(amaster, ptsname, NULL, NULL);
    if (pid != 0)
        return pid;

    /* Subprocess child. */
    setsid();

    child = open(ptsname, O_RDWR);
    if (child < 0)
        exit(child);

    dup2(child, STDIN_FILENO);
    dup2(child, STDOUT_FILENO);
    dup2(child, STDERR_FILENO);

    /* close the all fds except stdio */
    maxfd = sysconf(_SC_OPEN_MAX);
    for (fd = STDERR_FILENO + 1; fd < maxfd; ++fd)
        close(fd);

    retval = gethostname(hostname, sizeof(hostname));
    if (retval >= 0 && strcmp(hostname, "localhost"))
        setenv("HOSTNAME", hostname, 0);

    pwd = getpwuid(getuid());
    if (pwd) {
        chdir(pwd->pw_dir);
        setenv("HOME", pwd->pw_dir, 0);
        setenv("USER", pwd->pw_name, 0);
        setenv("LOGNAME", pwd->pw_name, 0);
        setenv("SHELL", pwd->pw_shell, 0);
    }

    value = NULL;
    if (shell->v2 && shell->term)
        value = shell->term;
    if (!value)
        value = getenv("TERM");
    if (!value)
        value = "xterm-256color";
    setenv("TERM", value, 0);

    /* sdbd ignored sigint and sigchld */
    signal(SIGINT, SIG_DFL);
    signal(SIGCHLD, SIG_DFL);

    execl(path, path, cmdline ? "-c" : "-", cmdline, NULL);
    exit(1);
}

static void
service_shell_close(struct sdbd_service *service)
{
    struct sdbd_shell_service *shell;

    bfdev_log_notice("shell close\n");
    shell = bfdev_container_of(service, struct sdbd_shell_service, service);
    send_close(shell->service.sctx, 0, shell->service.remote);
    kill(shell->pid, SIGKILL);

    bfenv_eproc_event_remove(service->sctx->eproc, &shell->event);
    bfenv_eproc_timer_remove(service->sctx->eproc, &service->timer);
    bfdev_free(NULL, shell->term);
    close(shell->event.fd);

    bfdev_array_release(&service->stream);
    bfdev_radix_free(&service->sctx->services, service->local);
    bfdev_free(NULL, service);
}

static int
service_shell_write(struct sdbd_service *service, void *data, size_t length)
{
    struct sdbd_shell_service *shell;
    struct shell_data *shellmsg;
    uint32_t cmd, size;
    ssize_t retlen;
    int retval;

    shell = bfdev_container_of(service, struct sdbd_shell_service, service);
    bfdev_log_debug("shell write: inprogress %zu\n", shell->inprogress);
    if (!shell->v2) {
        retval = sdbd_write(shell->event.fd, data, length);
        if (retval < 0)
            return retval;

        return -BFDEV_ENOERR;
    }

    while (length) {
        if (shell->inprogress) {
            size = bfdev_min(shell->inprogress, length);
            bfdev_log_debug("shell write: write %u\n", size);
            shell->inprogress -= size;

            switch (shell->cmd) {
                case SHELL_CMD_STDIN:
                    retval = sdbd_write(shell->event.fd, data, size);
                    if (retval < 0)
                        return retval;
                    break;

                case SHELL_CMD_WINSIZE: {
                    int rows, cols, xpixs, ypixs;
                    struct winsize wsize;
                    char *value;

                    retval = stream_accumulate(&shell->service,
                        shell->size, data, size);
                    if (retval < 0) {
                        if (retval == -BFDEV_EAGAIN)
                            break;

                        bfdev_log_err("shell write: append winsize failed\n");
                        return retval;
                    }

                    retval = stream_append(&shell->service, "", 1);
                    if (retval < 0) {
                        bfdev_log_err("shell write: append zero failed\n");
                        return retval;
                    }

                    value = bfdev_array_data(&shell->service.stream, 0);
                    BFDEV_BUG_ON(!value);

                    bfdev_log_debug("shell write: winsize '%s'\n", value);
                    if (sscanf(value, "%dx%d,%dx%d", &rows, &cols,
                        &xpixs, &ypixs) != 4) {
                        bfdev_log_warn("shell write: winsize format error\n");
                        service_shell_close(service);
                        return -BFDEV_ENOERR;
                    }

                    bfdev_array_reset(&service->stream);
                    wsize.ws_row = rows;
                    wsize.ws_col = cols;
                    wsize.ws_xpixel = xpixs;
                    wsize.ws_ypixel = ypixs;
                    ioctl(shell->event.fd, TIOCSWINSZ, &wsize);
                    break;
                }
            }

            length -= size;
            data += size;

            continue;
        }

        retlen = stream_accumulate(&shell->service, sizeof(*shellmsg), data, length);
        if (retlen < 0) {
            if (retlen == -BFDEV_EAGAIN) {
                bfdev_log_debug("shell write: wait header\n");
                return -BFDEV_ENOERR;
            }

            bfdev_log_debug("shell write: wait failed\n");
            return retlen;
        }

        shellmsg = bfdev_array_data(&shell->service.stream, 0);
        BFDEV_BUG_ON(!shellmsg);

        cmd = shellmsg->id;
        size = bfdev_le32_to_cpu(shellmsg->size);
        bfdev_array_reset(&shell->service.stream);

        bfdev_log_debug("shell write: cmd %d size %u\n", cmd, size);

        length -= retlen;
        data += retlen;

        switch (cmd) {
            case SHELL_CMD_STDIN:
            case SHELL_CMD_WINSIZE:
                shell->cmd = cmd;
                shell->size = size;
                break;

            case SHELL_CMD_CLOSE:
            default:
                service_shell_close(service);
                return -BFDEV_ENOERR;
        }

        if (size > service->sctx->max_payload) {
            service_shell_close(service);
            return -BFDEV_ENOERR;
        }

        shell->inprogress = size;
    }

    return -BFDEV_ENOERR;
}

static int
service_shell_handle(bfenv_eproc_event_t *event, void *pdata)
{
    struct sdbd_shell_service *shell;
    struct shell_data shellmsg;
    uint8_t buffer[MAX_PAYLOAD];
    ssize_t length;
    int retval;

    /* shell exit */
    shell = pdata;
    if (bfenv_eproc_error_test(&event->events)) {
        bfdev_log_info("shell handled: disconnected\n");
        service_shell_close(&shell->service);
        return -BFDEV_ENOERR;
    }

    length = read(event->fd, buffer, shell->service.sctx->max_payload);
    if (length <= 0)
        return -BFDEV_EIO;

    if (!shell->v2) {
        retval = send_data(shell->service.sctx, shell->service.local,
            shell->service.remote, buffer, length);
        if (retval < 0)
            return retval;

        return -BFDEV_ENOERR;
    }

    shellmsg.id = SHELL_CMD_STDOUT;
    shellmsg.size = bfdev_cpu_to_le32(length);

    retval = send_data(shell->service.sctx, shell->service.local,
        shell->service.remote, &shellmsg, sizeof(shellmsg));
    if (retval < 0)
        return retval;

    retval = send_data(shell->service.sctx, shell->service.local,
        shell->service.remote, buffer, length);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static struct sdbd_service *
service_shell_open(struct sdbd_ctx *sctx, char *cmdline)
{
    struct sdbd_shell_service *shell;
    struct sdbd_service **psrv;
    int amaster, retval;
    pid_t pid;

    bfdev_log_notice("shell open: cmdline '%s'\n", cmdline);
    shell = bfdev_zalloc(NULL, sizeof(*shell));
    if (!shell)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);

    for (;;) {
        unsigned long offset;
        char *parse, sch;

        parse = cmdline;
        offset = strcspn(cmdline, ",:");
        if (!cmdline[offset])
            return NULL;

        cmdline += offset;
        sch = *cmdline;
        *cmdline++ = '\0';

        bfdev_log_debug("shell open: parse '%s'\n", parse);
        if (!strcmp(parse, SHELL_FUTURE_V2)) {
            bfdev_log_debug("shell open: enable v2\n");
            shell->v2 = true;
        }

        if (!strncmp(parse, SHELL_FUTURE_TERM, sizeof(SHELL_FUTURE_TERM) - 1)) {
            parse += sizeof(SHELL_FUTURE_TERM) - 1;
            bfdev_log_debug("shell open: use term '%s'\n", parse);
            shell->term = bfdev_strdup(NULL, parse);
            if (!shell->term)
                return BFDEV_ERR_PTR(-BFDEV_ENOMEM);
        }

        if (sch == ':')
            break;
    }

    if (!*cmdline)
        cmdline = NULL;

    shell->service.sctx = sctx;
    shell->service.remote = sctx->args[0];
    shell->service.local = ++sctx->sockid;
    shell->service.write = service_shell_write;
    shell->service.close = service_shell_close;
    bfdev_array_init(&shell->service.stream, NULL, sizeof(uint8_t));

    pid = spawn_shell(shell, &amaster, sdbd_shell, cmdline);
    if (pid < 0)
        return BFDEV_ERR_PTR(-BFDEV_EFAULT);

    shell->pid = pid;
    shell->event.fd = amaster;
    shell->event.flags = BFENV_EPROC_READ;
    shell->event.func = service_shell_handle;
    shell->event.pdata = shell;

    retval = bfenv_eproc_event_add(sctx->eproc, &shell->event);
    if (retval < 0)
        return BFDEV_ERR_PTR(retval);

    psrv = bfdev_radix_alloc(&sctx->services, sctx->sockid);
    if (!psrv)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);
    *psrv = &shell->service;

    return &shell->service;
}

static struct sdbd_service *
service_reboot_open(struct sdbd_ctx *sctx, char *cmdline)
{
    struct sdbd_service *service;
    char buff[MAX_PAYLOAD];

    bfdev_log_notice("reboot open: cmdline '%s'\n", cmdline);
    bfdev_scnprintf(buff, sizeof(buff), ":reboot '%s'", cmdline);
    service = service_shell_open(sctx, buff);
    if (!service)
        return NULL;

    return service;
}

static struct sdbd_service *
service_remount_open(struct sdbd_ctx *sctx, char *cmdline)
{
    struct sdbd_service *service;

    bfdev_log_notice("remount open\n");
    service = service_shell_open(sctx, ":mount -o remount,rw /system");
    if (!service)
        return NULL;

    return service;
}

static void
service_sync_close(struct sdbd_service *service)
{
    struct sdbd_sync_service *sync;

    bfdev_log_notice("sync close\n");
    sync = bfdev_container_of(service, struct sdbd_sync_service, service);
    send_close(sync->service.sctx, 0, sync->service.remote);

    if (sync->fd > 0)
        close(sync->fd);

    bfenv_eproc_event_remove(service->sctx->eproc, &sync->event);
    bfenv_eproc_timer_remove(service->sctx->eproc, &service->timer);
    bfenv_iothread_destory(sync->fileio, NULL, NULL);

    bfdev_array_release(&service->stream);
    bfdev_radix_free(&service->sctx->services, service->local);
    bfdev_free(NULL, sync);
}

static int
service_sync_status(struct sdbd_sync_service *sync, uint32_t cmd, char *msg)
{
    struct sync_status syncmsg;
    size_t length;
    int retval;

    length = strlen(msg);
    syncmsg.id = bfdev_cpu_to_le32(cmd);
    syncmsg.msglen = bfdev_cpu_to_le32(length);

    retval = send_data(sync->service.sctx, sync->service.local,
        sync->service.remote, &syncmsg, sizeof(syncmsg));
    if (retval < 0)
        return retval;

    if (length) {
        retval = send_data(sync->service.sctx, sync->service.local,
            sync->service.remote, msg, length);
        if (retval < 0)
            return retval;
    }

    return -BFDEV_ENOERR;
}

static int
service_sync_fail(struct sdbd_sync_service *sync, char *msg)
{
    int retval;

    bfdev_log_warn("service sync fail: '%s'\n", msg);
    retval = service_sync_status(sync, SYNC_CMD_FAIL, msg);
    if (retval < 0)
        return retval;

    service_sync_close(&sync->service);

    return -BFDEV_ENOERR;
}

static int
service_sync_stat(struct sdbd_sync_service *sync, char *filename)
{
    struct sync_stat syncmsg;
    struct stat stat;
    int retval;

    bzero(&syncmsg, sizeof(syncmsg));
    syncmsg.id = bfdev_cpu_to_le32(SYNC_CMD_STAT);

    if (!lstat(filename, &stat)) {
        syncmsg.mode = bfdev_cpu_to_le32(stat.st_mode);
        syncmsg.size = bfdev_cpu_to_le32(stat.st_size);
        syncmsg.time = bfdev_cpu_to_le32(stat.st_mtime);
    }

    retval = send_data(sync->service.sctx, sync->service.local,
        sync->service.remote, &syncmsg, sizeof(syncmsg));
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_sync_list(struct sdbd_sync_service *sync, char *filename)
{
    char buffer[PATH_MAX + 1], *fname;
    struct sync_directry syncmsg;
    struct stat stbuf;
    size_t pathlen, filelen;
    struct dirent *dirent;
    int retval;
    DIR *dir;

    pathlen = strlen(filename);
    BFDEV_BUG_ON(pathlen + 1 > PATH_MAX);

    memcpy(buffer, filename, pathlen);
    buffer[pathlen++] = '/';
    fname = buffer + pathlen;

    dir = opendir(filename);
    if (!dir)
        goto done;

    syncmsg.id = bfdev_cpu_to_le32(SYNC_CMD_DENT);
    while ((dirent = readdir(dir))) {
        filelen = strlen(dirent->d_name);
        BFDEV_BUG_ON(pathlen + filelen > PATH_MAX);

        strcpy(fname, dirent->d_name);
        if (!lstat(buffer, &stbuf)) {
            syncmsg.mode = bfdev_cpu_to_le32(stbuf.st_mode);
            syncmsg.size = bfdev_cpu_to_le32(stbuf.st_size);
            syncmsg.time = bfdev_cpu_to_le32(stbuf.st_mtime);
            syncmsg.namelen = bfdev_cpu_to_le32(filelen);

            retval = send_data(sync->service.sctx, sync->service.local,
                sync->service.remote, &syncmsg, sizeof(syncmsg));
            if (retval < 0)
                return retval;

            retval = send_data(sync->service.sctx, sync->service.local,
                sync->service.remote, dirent->d_name, filelen);
            if (retval < 0)
                return retval;
        }
    }

    closedir(dir);

done:
    syncmsg.id = bfdev_cpu_to_le32(SYNC_CMD_DONE);
    syncmsg.mode = bfdev_cpu_to_le32(0);
    syncmsg.size = bfdev_cpu_to_le32(0);
    syncmsg.time = bfdev_cpu_to_le32(0);
    syncmsg.namelen = bfdev_cpu_to_le32(0);

    retval = send_data(sync->service.sctx, sync->service.local,
        sync->service.remote, &syncmsg, sizeof(syncmsg));
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
sync_recv_batch_write(struct sdbd_sync_service *sync, void *data, size_t size)
{
    struct sync_data syncmsg;
    size_t xfer, total;
    void *batch;
    int retval;

    BFDEV_BUG_ON(bfdev_array_size(&sync->service.stream));
    for (; (xfer = bfdev_min(size, SYNC_MAXDATA)); size -= xfer) {
        syncmsg.id = bfdev_cpu_to_le32(SYNC_CMD_DATA);
        syncmsg.size = bfdev_cpu_to_le32(xfer);

        retval = stream_append(&sync->service, &syncmsg, sizeof(syncmsg));
        if (retval < 0)
            return retval;

        retval = stream_append(&sync->service, data, xfer);
        if (retval < 0)
            return retval;

        data += xfer;
    }

    batch = bfdev_array_data(&sync->service.stream, 0);
    total = bfdev_array_size(&sync->service.stream);
    BFDEV_BUG_ON(!batch);

    retval = send_datas(sync->service.sctx, sync->service.local,
        sync->service.remote, batch, total);
    if (retval < 0)
        return retval;

    bfdev_array_reset(&sync->service.stream);

    return -BFDEV_ENOERR;
}

static int
service_sync_recv_handle(bfenv_eproc_event_t *event, void *pdata)
{
    struct sdbd_sync_service *sync;
    bfenv_iothread_request_t request;
    struct sync_data syncmsg;
    unsigned long deepth;
    eventfd_t count;
    int retval;

    sync = pdata;
    retval = eventfd_read(event->fd, &count);
    if (retval < 0) {
        bfdev_log_err("sync recv handled: eventfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    bfdev_log_debug("sync recv handled: pending %" PRIu64 "\n", count);
    BFDEV_BUG_ON(count != 1);

    deepth = bfdev_fifo_get(&sync->fileio->done_works, &request);
    BFDEV_BUG_ON(deepth != 1);

    if (request.error) {
        retval = service_sync_fail(sync, "failed to read file");
        if (retval < 0)
            return retval;

        return -BFDEV_ENOERR;
    }

    switch (request.event) {
        case BFENV_IOTHREAD_EVENT_READ:
            break;

        default:
            BFDEV_BUG();
    }

    bfdev_log_debug("sync recv handled: readed %zd\n", request.size);
    if (!request.size) {
        syncmsg.id = bfdev_cpu_to_le32(SYNC_CMD_DONE);
        syncmsg.size = bfdev_cpu_to_le32(0);

        bfdev_log_info("shell recv handled: finish\n");
        retval = send_data(sync->service.sctx, sync->service.local,
            sync->service.remote, &syncmsg, sizeof(syncmsg));
        if (retval < 0)
            return retval;

        close(sync->fd);
        sync->fd = -1;

        return -BFDEV_ENOERR;
    }

    retval = sync_recv_batch_write(sync, &sync->buff, request.size);
    if (retval < 0)
        return retval;

    retval = bfenv_iothread_read(sync->fileio, sync->fd,
        &sync->buff, sync->batch);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_sync_recv(struct sdbd_sync_service *sync, char *filename)
{
    int retval;

    sync->fd = open(filename, O_RDONLY);
    if (sync->fd < 0) {
        bfdev_log_warn("sync recv: failed to open file '%s' error %d\n",
            filename, errno);

        retval = service_sync_fail(sync, "failed to open file");
        if (retval < 0)
            return retval;

        return -BFDEV_ECANCELED;
    }

    bfdev_log_debug("sync recv: batch size %zd\n", sync->batch);
    sync->event.func = service_sync_recv_handle;

    retval = bfenv_iothread_read(sync->fileio, sync->fd,
        &sync->buff, sync->batch);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
recursion_mkdir(char *dirname)
{
    char *curr;
    int ret;

    if (dirname[0] != '/')
        return -1;
    curr = dirname + 1;

    for (;;) {
        curr = strchr(curr, '/');
        if (!curr)
            break;

        *curr = '\0';
        ret = mkdir(dirname, 0755);
        *curr++ = '/';

        if ((ret < 0) && (errno != EEXIST)) {
            bfdev_log_err("recursion mkdir: error %d\n", errno);
            return -BFDEV_EACCES;
        }
    }

    return -BFDEV_ENOERR;
}

static int
sync_send_file_write(struct sdbd_service *service, void *data, size_t length)
{
    struct sdbd_sync_service *sync;
    struct sync_data *syncmsg;
    struct utimbuf utim;
    uint32_t cmd, size;
    ssize_t retlen;
    int retval;

    sync = bfdev_container_of(service, struct sdbd_sync_service, service);
    bfdev_log_debug("sync send file write: inprogress %zu\n", sync->inprogress);

    while (length) {
        if (sync->inprogress) {
            size = bfdev_min(sync->inprogress, length);
            bfdev_log_debug("sync send file write: write %d %u\n",
                sync->fd, size);

            if (sync->fd > 0) {
                retval = sdbd_write(sync->fd, data, size);
                if (retval < 0) {
                    close(sync->fd);
                    unlink(sync->filename);
                    sync->fd = -1;
                }
            }

            length -= size;
            data += size;
            sync->inprogress -= size;

            continue;
        }

        retlen = stream_accumulate(&sync->service,
            sizeof(*syncmsg), data, length);
        if (retlen < 0) {
            if (retlen == -BFDEV_EAGAIN) {
                bfdev_log_debug("sync send file write: wait header\n");
                return -BFDEV_ENOERR;
            }
            bfdev_log_err("sync send file write: wait failed\n");
            retval = retlen;
            goto failed;
        }

        syncmsg = bfdev_array_data(&sync->service.stream, 0);
        BFDEV_BUG_ON(!syncmsg);

        cmd = bfdev_le32_to_cpu(syncmsg->id);
        size = bfdev_le32_to_cpu(syncmsg->size);
        bfdev_array_reset(&sync->service.stream);

        bfdev_log_debug("sync send file write: cmd '%c%c%c%c' size %u\n",
            (cmd >> 0) & 0xff, (cmd >> 8) & 0xff, (cmd >> 16) & 0xff,
            (cmd >> 24) & 0xff, size);

        length -= retlen;
        data += retlen;

        switch (cmd) {
            case SYNC_CMD_DATA:
                break;

            case SYNC_CMD_DONE:
                if (sync->fd > 0) {
                    close(sync->fd);
                    sync->fd = -1;
                }

                utim.actime = size;
                utim.modtime = size;
                utime(sync->filename, &utim);

                bfdev_log_info("sync send file write: finish\n");
                retval = service_sync_status(sync, SYNC_CMD_OKAY, "");
                if (retval < 0)
                    goto failed;

                sync->service.write = service_sync_write;
                retval = service_sync_write(&sync->service, data, length);
                if (retval < 0)
                    goto failed;

                return -BFDEV_ENOERR;

            default:
                sync->service.write = service_sync_write;
                retval = service_sync_fail(sync, "invalid data message");
                if (retval < 0)
                    goto failed;

                return -BFDEV_ENOERR;
        }

        if (size > SYNC_MAXDATA) {
            sync->service.write = service_sync_write;
            retval = service_sync_fail(sync, "oversize data message");
            if (retval < 0)
                goto failed;

            return -BFDEV_ENOERR;
        }

        sync->inprogress = size;
    }

    return -BFDEV_ENOERR;

failed:
    if (sync->fd > 0)
        close(sync->fd);
    unlink(sync->filename);

    return retval;
}

static int
sync_send_file(struct sdbd_sync_service *sync, char *filename, mode_t mode,
               void *data, size_t length)
{
    int retval;

    sync->fd = open(filename, O_WRONLY | O_NONBLOCK |
        O_CREAT | O_EXCL, mode);
    if (sync->fd < 0 && errno == ENOENT) {
        recursion_mkdir(filename);

        /* no directory, try again */
        sync->fd = open(filename, O_WRONLY | O_NONBLOCK |
            O_CREAT | O_EXCL, mode);
    }

    if (sync->fd < 0 && errno == EEXIST) {
        /* file exist, try again */
        sync->fd = open(filename, O_WRONLY | O_NONBLOCK, mode);
    }

    if (sync->fd < 0) {
        bfdev_log_warn("sync send file: failed to open file '%s' error %d\n",
            filename, errno);

        retval = service_sync_fail(sync, "failed to open file");
        if (retval < 0)
            return retval;

        return -BFDEV_ECANCELED;
    }

    bfdev_log_debug("sync send file: started '%s' mode %o\n",
        filename, mode);

    sync->service.write = sync_send_file_write;
    retval = sync_send_file_write(&sync->service, data, length);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
sync_send_link(struct sdbd_sync_service *sync, char *filename)
{
    return -BFDEV_EPROTONOSUPPORT;
}

static int
service_sync_send(struct sdbd_sync_service *sync, char *filename, void *data, size_t length)
{
    bool islink, isreg;
    mode_t mode;
    char *flags;
    int retval;

    islink = false;
    isreg = false;

    flags = strrchr(filename,',');
    if (!flags)
        mode = 0644;
    else {
        *flags++ = '\0';
        mode = strtoul(flags, NULL, 0);
        islink = S_ISLNK(mode);
        isreg = S_ISREG(mode);
        mode &= 0777;
    }

    /* delete files before copying if they are regular or symlinks. */
    if (islink || isreg)
        unlink(filename);

    if (islink) {
        retval = sync_send_link(sync, filename);
        if (retval < 0)
            return retval;
        return -BFDEV_ENOERR;
    }

    mode |= (mode >> 3) & 0070;
    mode |= (mode >> 3) & 0007;

    retval = sync_send_file(sync, filename, mode, data, length);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_sync_write_name(struct sdbd_service *service, void *data, size_t length)
{
    struct sdbd_sync_service *sync;
    ssize_t retlen;
    char *name;
    int retval;

    sync = bfdev_container_of(service, struct sdbd_sync_service, service);
    retlen = stream_accumulate(service, sync->namelen, data, length);
    if (retlen < 0) {
        if (retlen == -BFDEV_EAGAIN) {
            bfdev_log_debug("sync write: wait header\n");
            return -BFDEV_ENOERR;
        }
        bfdev_log_err("sync write: wait failed\n");
        return retlen;
    }

    name = bfdev_array_data(&service->stream, 0);
    BFDEV_BUG_ON(!name);

    memcpy(sync->filename, name, sync->namelen);
    sync->filename[sync->namelen] = '\0';
    bfdev_array_reset(&service->stream);

    bfdev_log_notice("sync write name: '%s'\n", sync->filename);
    data += retlen;
    length -= retlen;

    switch (sync->cmd) {
        case SYNC_CMD_STAT: /* header + filename */
            retval = service_sync_stat(sync, sync->filename);
            if (retval < 0)
                return retval;
            goto finish;

        case SYNC_CMD_LIST: /* header + filename */
            retval = service_sync_list(sync, sync->filename);
            if (retval < 0)
                return retval;
            goto finish;

        case SYNC_CMD_RECV: /* header + filename */
            retval = service_sync_recv(sync, sync->filename);
            if (retval < 0) {
                if (retval == -BFDEV_ECANCELED)
                    return -BFDEV_ENOERR;
                return retval;
            }
            goto finish;

        case SYNC_CMD_SEND: /* header + filename + data */
            retval = service_sync_send(sync, sync->filename, data, length);
            if (retval < 0) {
                if (retval == -BFDEV_ECANCELED)
                    return -BFDEV_ENOERR;
                return retval;
            }
            break;

        default:
            BFDEV_BUG();
    }

    return -BFDEV_ENOERR;

finish:
    sync->service.write = service_sync_write;
    retval = service_sync_write(&sync->service, data, length);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_sync_write(struct sdbd_service *service, void *data, size_t length)
{
    struct sdbd_sync_service *sync;
    struct sync_request *syncmsg;
    ssize_t retlen;
    int retval;

    sync = bfdev_container_of(service, struct sdbd_sync_service, service);
    retlen = stream_accumulate(service, sizeof(*syncmsg), data, length);
    if (retlen < 0) {
        if (retlen == -BFDEV_EAGAIN) {
            bfdev_log_debug("sync write: wait header\n");
            return -BFDEV_ENOERR;
        }

        bfdev_log_debug("sync write: wait failed\n");
        return retlen;
    }

    syncmsg = bfdev_array_data(&service->stream, 0);
    BFDEV_BUG_ON(!syncmsg);

    sync->cmd = bfdev_le32_to_cpu(syncmsg->id);
    sync->namelen = bfdev_le32_to_cpu(syncmsg->namelen);
    bfdev_array_reset(&service->stream);

    data += retlen;
    length -= retlen;

    bfdev_log_notice("sync write: command '%c%c%c%c' namelen %u\n",
        (sync->cmd >> 0) & 0xff, (sync->cmd >> 8) & 0xff,
        (sync->cmd >> 16) & 0xff, (sync->cmd >> 24) & 0xff, sync->namelen);

    if (sync->namelen > SYNC_MAXNAME) {
        retval = service_sync_fail(sync, "namelen too big");
        if (retval < 0)
            return retval;

        return -BFDEV_ENOERR;
    }

    switch (sync->cmd) {
        case SYNC_CMD_STAT:
        case SYNC_CMD_LIST:
        case SYNC_CMD_RECV:
        case SYNC_CMD_SEND:
            break;

        case SYNC_CMD_QUIT:
            retval = send_close(service->sctx, 0, service->remote);
            if (retval < 0)
                return retval;
            return -BFDEV_ENOERR;

        default:
            retval = service_sync_fail(sync, "unknown command");
            if (retval < 0)
                return retval;
            return -BFDEV_ENOERR;
    }

    if (!sync->namelen) {
        retval = service_sync_fail(sync, "invalid namelen");
        if (retval < 0)
            return retval;

        return -BFDEV_ENOERR;
    }

    sync->service.write = service_sync_write_name;
    retval = service_sync_write_name(&sync->service, data, length);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static struct sdbd_service *
service_sync_open(struct sdbd_ctx *sctx, char *cmdline)
{
    struct sdbd_sync_service *sync;
    struct sdbd_service **psrv;
    size_t slots, batch;
    int retval;

    slots = BFDEV_DIV_ROUND_UP(sctx->max_payload, SYNC_MAXDATA);
    batch = sctx->max_payload - sizeof(struct sync_data) * slots;

    sync = bfdev_zalloc(NULL, sizeof(*sync) + batch);
    if (!sync)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);

    sync->batch = batch;
    sync->service.sctx = sctx;
    sync->service.remote = sctx->args[0];
    sync->service.local = ++sctx->sockid;
    sync->service.write = service_sync_write;
    sync->service.close = service_sync_close;
    bfdev_array_init(&sync->service.stream, NULL, sizeof(uint8_t));

    sync->fileio = bfenv_iothread_create(NULL, 1, BFENV_IOTHREAD_SIGREAD);
    if (!sync->fileio) {
        bfdev_log_err("sync open: failed to create iothread\n");
        return BFDEV_ERR_PTR(-BFDEV_EFAULT);
    }

    sync->event.fd = sync->fileio->eventfd;
    sync->event.flags = BFENV_EPROC_READ;
    sync->event.pdata = sync;

    retval = bfenv_eproc_event_add(sync->service.sctx->eproc, &sync->event);
    if (retval < 0) {
        bfdev_log_err("sync open: failed to add event\n");
        return BFDEV_ERR_PTR(-BFDEV_EFAULT);
    }

    psrv = bfdev_radix_alloc(&sctx->services, sctx->sockid);
    if (!psrv)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);
    *psrv = &sync->service;

    return &sync->service;
}

static const struct {
    const char *name;
    struct sdbd_service *(*open)(struct sdbd_ctx *sctx, char *cmdline);
} services[] = {
    {
        .name = "shell",
        .open = service_shell_open,
    }, {
        .name = "reboot:",
        .open = service_reboot_open,
    }, {
        .name = "remount:",
        .open = service_remount_open,
    }, {
        .name = "sync:",
        .open = service_sync_open,
    },
};

static int
service_timemout(bfenv_eproc_timer_t *timer, void *pdata)
{
    struct sdbd_service *service;

    service = pdata;
    bfdev_log_notice("service timeout: local %u remote %u\n",
        service->local, service->remote);
    service->close(service);

    return -BFDEV_ENOERR;
}

static int
service_kick(struct sdbd_service *service)
{
    struct sdbd_ctx *sctx;
    int retval;

    sctx = service->sctx;
    bfdev_log_debug("service kick: local %u remote %u\n",
        service->local, service->remote);

    bfenv_eproc_timer_remove(sctx->eproc, &service->timer);
    retval = bfenv_eproc_timer_add(sctx->eproc, &service->timer, sdbd_timeout);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_open(struct sdbd_ctx *sctx, char *cmdline)
{
    struct sdbd_service *service;
    unsigned int index;
    int retval;

    for (index = 0; index < BFDEV_ARRAY_SIZE(services); ++index) {
        size_t length;

        length = strlen(services[index].name);
        if (strncmp(cmdline, services[index].name, length))
            continue;

        cmdline += length;
        service = services[index].open(sctx, cmdline);
        if (!service)
            break;

        if (BFDEV_IS_INVAL(service))
            return BFDEV_PTR_INVAL(service);

        retval = send_okay(sctx, service->local, service->remote);
        if (retval < 0)
            return retval;

        service->timer.func = service_timemout;
        service->timer.pdata = service;
        retval = bfenv_eproc_timer_add(sctx->eproc, &service->timer,
            sdbd_timeout);
        if (retval < 0)
            return retval;

        return -BFDEV_ENOERR;
    }

    bfdev_log_warn("service open: unsupported service\n");
    retval = send_close(sctx, 0, sctx->args[0]);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_write(struct sdbd_ctx *sctx, uint8_t *payload)
{
    struct sdbd_service *service, **psrv;
    uint32_t local, remote;
    int retval;

    local = sctx->args[1];
    psrv = bfdev_radix_find(&sctx->services, local);
    if (!psrv) {
        bfdev_log_notice("service write: failed connect to %d\n", local);
        return -BFDEV_ENOERR;
    }

    service = *psrv;
    remote = service->remote;

    retval = service_kick(service);
    if (retval < 0)
        return retval;

    /* service could close in write */
    retval = service->write(service, payload, sctx->length);
    if (retval < 0)
        return retval;

    retval = send_okay(sctx, local, remote);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_okay(struct sdbd_ctx *sctx)
{
    struct sdbd_service *service, **psrv;
    uint32_t local;
    int retval;

    local = sctx->args[1];
    psrv = bfdev_radix_find(&sctx->services, local);
    if (!psrv) {
        bfdev_log_notice("service okay: failed connect to %d\n", local);
        return -BFDEV_ENOERR;
    }

    service = *psrv;
    retval = service_kick(service);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static void
service_close(struct sdbd_ctx *sctx)
{
    struct sdbd_service *service, **psrv;
    uint32_t local;

    local = sctx->args[1];
    psrv = bfdev_radix_find(&sctx->services, local);
    if (!psrv) {
        bfdev_log_debug("service close: already close\n");
        return;
    }

    service = *psrv;
    service->close(service);
}

static void
service_close_all(struct sdbd_ctx *sctx)
{
    struct sdbd_service *service, **psrv;
    uintptr_t offset;

    bfdev_log_debug("service close all\n");
    bfdev_radix_for_each(psrv, &sctx->services, &offset) {
        service = *psrv;
        service->close(service);
    }
}

static int
parse_connect(struct sdbd_ctx *sctx, uint8_t *payload)
{
    uint32_t version, max_payload;

    version = sctx->args[0];
    max_payload = sctx->args[1];

    bfdev_log_info("parse connect: version %d payload %d\n",
        version, max_payload);

    if (!max_payload) {
        bfdev_log_err("parse connect: invalid payload\n");
        return -BFDEV_EINVAL;
    }

    bfdev_min_adj(version, ADB_VERSION);
    bfdev_min_adj(max_payload, MAX_PAYLOAD);

    sctx->version = version;
    sctx->max_payload = max_payload;

    return -BFDEV_ENOERR;
}

static int
adb_connect(struct sdbd_ctx *sctx, uint8_t *payload)
{
    int retval;

    bfdev_log_notice("adb connected\n");
    retval = parse_connect(sctx, payload);
    if (retval < 0)
        return retval;

    if (sdbd_auth)
        retval = send_auth_request(sctx);
    else {
        sctx->verified = true;
        retval = send_connect(sctx);
    }

    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
adb_auth(struct sdbd_ctx *sctx, uint8_t *payload)
{
    int retval;

    switch (sctx->args[0]) {
        case AUTH_TOKEN:
            bfdev_log_debug("handle auth: auth token\n");
            /* Do nothing */
            break;

        case AUTH_RSAPUBLICKEY:
            bfdev_log_debug("handle auth: auth rsapublickey\n");
            /* Do nothing */
            break;

        case AUTH_SIGNATURE:
            bfdev_log_debug("handle auth: auth signature\n");
            retval = auth_verify(sctx, payload, sctx->length);
            if (retval < 0)
                return retval;

            if (retval == false) {
                bfdev_log_debug("handle auth: auth failed\n");
                usleep(AUTH_FAIL_DELAY * 1000);
                retval = send_auth_request(sctx);
            } else {
                bfdev_log_debug("handle auth: auth succeed\n");
                sctx->verified = true;
                retval = send_connect(sctx);
            }

            if (retval < 0)
                return retval;
            break;

        default:
            bfdev_log_warn("handle auth: unknow\n");
            break;
    }

    return -BFDEV_ENOERR;
}

static int
handle_packet(struct sdbd_ctx *sctx, uint32_t cmd, uint8_t *payload)
{
    int retval;

    bfdev_log_info("handled packet: '%c%c%c%c' (%u %u) length %u\n",
        (cmd >> 0) & 0xff, (cmd >> 8) & 0xff, (cmd >> 16) & 0xff,
        (cmd >> 24) & 0xff, sctx->args[0], sctx->args[1], sctx->length);
    bfdev_log_debug("packet payload: '%s'\n", payload);

    switch (cmd) {
        case PCMD_CNXN:
            retval = adb_connect(sctx, payload);
            if (retval < 0)
                return retval;
            break;

        case PCMD_AUTH:
            retval = adb_auth(sctx, payload);
            if (retval < 0)
                return retval;
            break;

        case PCMD_OPEN:
            if (!sctx->verified)
                break;
            retval = service_open(sctx, (void *)payload);
            if (retval < 0)
                return retval;
            break;

        case PCMD_CLSE:
            if (!sctx->verified)
                break;
            service_close(sctx);
            break;

        case PCMD_WRTE:
            if (!sctx->verified)
                break;
            retval = service_write(sctx, payload);
            if (retval < 0)
                return retval;
            break;

        case PCMD_OKAY:
            if (!sctx->verified)
                break;
            retval = service_okay(sctx);
            if (retval < 0)
                return retval;
            break;

        default:
            bfdev_log_warn("handled packet: unsupported command\n");
            retval = send_close(sctx, 0, sctx->args[0]);
            if (retval < 0)
                return retval;
            break;
    }

    return -BFDEV_ENOERR;
}

static int
sdbd_usb_recv_handle(struct sdbd_ctx *sctx)
{
    uint8_t payload[MAX_PAYLOAD + 1];
    int retval;

    sctx->command = bfdev_le32_to_cpu(sctx->msgbuff.command);
    sctx->args[0] = bfdev_le32_to_cpu(sctx->msgbuff.args[0]);
    sctx->args[1] = bfdev_le32_to_cpu(sctx->msgbuff.args[1]);
    sctx->magic = bfdev_le32_to_cpu(sctx->msgbuff.magic);
    sctx->length = bfdev_le32_to_cpu(sctx->msgbuff.length);
    sctx->check = bfdev_le32_to_cpu(sctx->msgbuff.cksum);

    /* check header */
    if (sctx->command != ~sctx->magic || sctx->length > sctx->max_payload) {
        bfdev_log_err("usb recv: packet header format error\n");
        return -BFDEV_EBADMSG;
    }

    if (sctx->length) {
        bfdev_log_debug("usb recv: read payload %u\n", sctx->length);

        retval = sdbd_read(sctx->fd_out, payload, sctx->length);
        if (retval < 0) {
            bfdev_log_err("usb recv: failed to get payload %d\n", errno);
            return -BFDEV_EBADMSG;
        }

        if (payload_cksum(payload, sctx->length) != sctx->check) {
            bfdev_log_err("usb recv: payload cksum error\n");
            return -BFDEV_EREMOTEIO;
        }
    }

    payload[sctx->length] = '\0';
    retval = handle_packet(sctx, sctx->command, payload);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
sdbd_usb_out_handle(bfenv_eproc_event_t *event, void *pdata)
{
    bfenv_iothread_request_t request;
    struct sdbd_ctx *sctx;
    unsigned long deepth;
    eventfd_t count;
    int retval;

    sctx = pdata;
    retval = eventfd_read(event->fd, &count);
    if (retval < 0) {
        bfdev_log_err("usb out handled: eventfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    bfdev_log_debug("usb out handled: pending %" PRIu64 "\n", count);
    BFDEV_BUG_ON(count != 1);

    deepth = bfdev_fifo_get(&sctx->usbio_out->done_works, &request);
    BFDEV_BUG_ON(deepth != 1);

    if (request.error) {
        if (request.error == ESHUTDOWN)
            return -BFDEV_ESHUTDOWN;

        bfdev_log_err("usb out handled: error %d\n", request.error);
        return -BFDEV_EFAULT;
    }

    if (request.size != sizeof(sctx->msgbuff)) {
        bfdev_log_info("usb out handled: packet size mismatch %zu\n",
            request.size);
        goto finish;
    }

    switch (request.event) {
        case BFENV_IOTHREAD_EVENT_READ:
            retval = sdbd_usb_recv_handle(sctx);
            if (retval < 0)
                return retval;
            break;

        default:
            BFDEV_BUG();
    }

finish:
    /* reregister usbio read handler */
    bfdev_log_debug("usbio read: message\n");
    retval = bfenv_iothread_read(sctx->usbio_out, sctx->fd_out,
        &sctx->msgbuff, sizeof(sctx->msgbuff));
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
sdbd_usb_in_handle(bfenv_eproc_event_t *event, void *pdata)
{
    bfenv_iothread_request_t request;
    struct sdbd_ctx *sctx;
    unsigned long deepth;
    eventfd_t count;
    int retval;

    sctx = pdata;
    retval = eventfd_read(event->fd, &count);
    if (retval < 0) {
        bfdev_log_err("usb in handled: eventfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    bfdev_log_debug("usb in handled: pending %" PRIu64 "\n", count);
    BFDEV_BUG_ON(count < 1);

    while (count--) {
        deepth = bfdev_fifo_get(&sctx->usbio_in->done_works, &request);
        BFDEV_BUG_ON(deepth != 1);

        if (request.error) {
            if (request.error == ESHUTDOWN)
                return -BFDEV_ESHUTDOWN;

            bfdev_log_err("usb in handled: error %d\n", request.error);
            return -BFDEV_EFAULT;
        }

        switch (request.event) {
            case BFENV_IOTHREAD_EVENT_WRITE:
                bfdev_free(NULL, request.buffer);
                break;

            default:
                BFDEV_BUG();
        }
    }

    return retval;
}

static int
sdbd_signal_handle(bfenv_eproc_event_t *event, void *pdata)
{
    struct signalfd_siginfo si;
    int retval;

    retval = read(event->fd, &si, sizeof(si));
    if (retval < 0) {
        bfdev_log_err("signal handled: sigfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    switch (si.ssi_signo) {
        case SIGCHLD:
            bfdev_log_debug("signal handled: release childrens\n");
            waitpid(-1, NULL, WNOHANG);
            break;

        case SIGINT:
            return -BFDEV_ECANCELED;

        default:
            BFDEV_BUG();
    }

    return -BFDEV_ENOERR;
}

static int
usb_init_send(int fd)
{
    if (write(fd, &adb_desc, sizeof(adb_desc)) != sizeof(adb_desc)) {
        bfdev_log_err("send adb descriptors failed\n");
        return -BFDEV_EFAULT;
    }

    if (write(fd, &adb_str, sizeof(adb_str)) != sizeof(adb_str)) {
        bfdev_log_err("send adb strings failed\n");
        return -BFDEV_EFAULT;
    }

    return -BFDEV_ENOERR;
}

static int
usb_init(struct sdbd_ctx *sctx)
{
    int retval;

    sctx->fd_ctr = open(USB_FFS_ADB_CTL, O_RDWR);
    if (sctx->fd_ctr < 0) {
        bfdev_log_err("open usb control failed: '%s'\n", USB_FFS_ADB_CTL);
        return -BFDEV_EACCES;
    }

    retval = usb_init_send(sctx->fd_ctr);
    if (retval < 0)
        return retval;

    sctx->fd_out = open(USB_FFS_ADB_OUT, O_RDONLY);
    if (sctx->fd_out < 0) {
        bfdev_log_err("open usb out failed: '%s'\n", USB_FFS_ADB_OUT);
        return -BFDEV_EACCES;
    }

    sctx->fd_in = open(USB_FFS_ADB_IN, O_WRONLY);
    if (sctx->fd_in < 0) {
        bfdev_log_err("open usb in failed: '%s'\n", USB_FFS_ADB_IN);
        return -BFDEV_EACCES;
    }

    bfdev_log_debug("usb init: read message\n");
    retval = bfenv_iothread_read(sctx->usbio_out, sctx->fd_out,
        &sctx->msgbuff, sizeof(sctx->msgbuff));
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static void
usb_close(struct sdbd_ctx *sctx)
{
    close(sctx->fd_ctr);
    close(sctx->fd_out);
    close(sctx->fd_in);
}

static int
usb_kick(struct sdbd_ctx *sctx)
{
    int retval;

    bfdev_log_debug("usb kick\n");
    if ((retval = ioctl(sctx->fd_out, FUNCTIONFS_CLEAR_HALT)) ||
        (retval = ioctl(sctx->fd_in, FUNCTIONFS_CLEAR_HALT)))
        return -BFDEV_EIO;

    usb_close(sctx);
    retval = usb_init(sctx);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
signal_init(struct sdbd_ctx *sctx)
{
    sigset_t mask;
    int sigfd, retval;

    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGCHLD);

    if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0)
        return -BFDEV_EFAULT;

    sigfd = signalfd(-1, &mask, 0);
    if (sigfd < 0)
        return -BFDEV_EFAULT;

    sctx->sigev.fd = sigfd;
    sctx->sigev.flags = BFENV_EPROC_READ;
    sctx->sigev.priority = 100;
    sctx->sigev.func = sdbd_signal_handle;
    sctx->sigev.pdata = sctx;

    retval = bfenv_eproc_event_add(sctx->eproc, &sctx->sigev);
    if (retval < 0)
        return retval;

    return -BFDEV_ENOERR;
}

static int
sdbd_exception(int error)
{
    const char *einfo;

    if (!bfdev_errname(error, &einfo))
        einfo = "Unknow error";
    bfdev_log_crit("critical exception [%d]: '%s'\n", error, einfo);

    return error;
}

static int
read_keys(const char *path)
{
    char line[4096], *sep;
    FILE *file;
    unsigned int count;
    int retval;

    file = fopen(path, "r");
    if (!file) {
        bfdev_log_err("read keys: failed to open file\n");
        return -BFDEV_EACCES;
    }

    while (fgets(line, sizeof(line), file)) {
        struct sdbd_rsa_publickey *key;
        struct rsa_publickey *rawkey;
        uint8_t buff[600];
        size_t size;

        sep = strpbrk(line, " \t");
        if (sep)
            *sep = '\0';

        size = bfdev_base64_decode_length(sep - line);
        bfdev_log_debug("read keys: size %zu\n", size);

        if (size != sizeof(*rawkey) + 1) {
            bfdev_log_warn("read keys: invalid base64 length\n");
            continue;
        }

        retval = bfdev_base64_decode((void *)buff, line, sep - line);
        if (retval < 0) {
            bfdev_log_warn("read keys: invalid base64 data\n");
            continue;
        }

        rawkey = (void *)buff;
        if (bfdev_le32_to_cpu(rawkey->len) != RSANUMU32S) {
            bfdev_log_warn("read keys: invalid key length\n");
            continue;
        }

        if (bfdev_le32_to_cpu(rawkey->exponent) != 3 &&
            bfdev_le32_to_cpu(rawkey->exponent) != 65537) {
            bfdev_log_notice("read keys: unsupported exponent\n");
            continue;
        }

        key = bfdev_malloc(NULL, sizeof(*key));
        if (!key)
            return -BFDEV_ENOMEM;

        key->len = bfdev_le32_to_cpu(rawkey->len);
        key->n0inv = bfdev_le32_to_cpu(rawkey->n0inv);
        key->exponent = bfdev_le32_to_cpu(rawkey->exponent);
        bfdev_list_add(&sdbd_auth_keys, &key->list);

        for (count = 0; count < RSANUMU32S; ++count) {
            key->n[count] = bfdev_le32_to_cpu(rawkey->n[count]);
            key->rr[count] = bfdev_le32_to_cpu(rawkey->rr[count]);
        }
    }

    fclose(file);

    return -BFDEV_ENOERR;
}

static int
load_keys(void)
{
    unsigned int count;
    struct stat stbuf;
    int retval;

    if (sdbd_auth_file) {
        retval = read_keys(sdbd_auth_file);
        if (retval < 0)
            return retval;
        goto finish;
    }

    for (count = 0; count < BFDEV_ARRAY_SIZE(auth_key_paths); ++count) {
        const char *path;

        path = auth_key_paths[count];
        bfdev_log_debug("load keys: file '%s'\n", path);

        if (stat(path, &stbuf)) {
            bfdev_log_debug("load keys: not found\n");
            continue;
        }

        retval = read_keys(path);
        if (retval < 0)
            return retval;
    }

finish:
    sdbd_auth = !bfdev_list_check_empty(&sdbd_auth_keys);
    return -BFDEV_ENOERR;
}

static int
sdbd(void)
{
    struct sdbd_ctx sctx;
    uint64_t seed;
    int retval;

    bzero(&sctx, sizeof(sctx));
    sctx.services = BFDEV_RADIX_INIT(&sctx.services, NULL);

    sctx.eproc = bfenv_eproc_create(NULL, "epoll");
    if (!sctx.eproc) {
        bfdev_log_err("eproc create failed\n");
        goto error;
    }

    retval = load_keys();
    if (retval < 0) {
        bfdev_log_err("failed to load auth keys\n");
        goto error;
    }

    retval = path_read("/dev/random", (void *)&seed, sizeof(seed));
    if (retval != sizeof(seed)) {
        bfdev_log_err("failed to read seed\n");
        goto error;
    }

    bfdev_prandom_init(&sctx.rand);
    bfdev_prandom_seed(&sctx.rand, seed);

    retval = signal_init(&sctx);
    if (retval < 0) {
        bfdev_log_err("signal initialization failed\n");
        goto error;
    }

    sctx.usbio_out = bfenv_iothread_create(NULL, 1,
        BFENV_IOTHREAD_SIGREAD);
    if (!sctx.usbio_out) {
        bfdev_log_err("usbio out iothread create failed\n");
        goto error;
    }

    sctx.usbio_in = bfenv_iothread_create(NULL, USB_FIFO_DEPTH,
        BFENV_IOTHREAD_SIGWRITE);
    if (!sctx.usbio_in) {
        bfdev_log_err("usbio in iothread create failed\n");
        goto error;
    }

    sctx.usbev_out.fd = sctx.usbio_out->eventfd;
    sctx.usbev_out.flags = BFENV_EPROC_READ;
    sctx.usbev_out.priority = -100;
    sctx.usbev_out.func = sdbd_usb_out_handle;
    sctx.usbev_out.pdata = &sctx;

    sctx.usbev_in.fd = sctx.usbio_in->eventfd;
    sctx.usbev_in.flags = BFENV_EPROC_READ;
    sctx.usbev_in.priority = -100;
    sctx.usbev_in.func = sdbd_usb_in_handle;
    sctx.usbev_in.pdata = &sctx;

    retval = bfenv_eproc_event_add(sctx.eproc, &sctx.usbev_out);
    if (retval < 0) {
        bfdev_log_err("register usb out event failed\n");
        goto error;
    }

    retval = bfenv_eproc_event_add(sctx.eproc, &sctx.usbev_in);
    if (retval < 0) {
        bfdev_log_err("register usb in event failed\n");
        goto error;
    }

    sctx.version = ADB_VERSION;
    sctx.max_payload = MAX_PAYLOAD;

    retval = usb_init(&sctx);
    if (retval < 0) {
        bfdev_log_err("usb initialization failed\n");
        goto error;
    }

    for (;;) {
        retval = bfenv_eproc_run(sctx.eproc, BFENV_TIMEOUT_MAX);
        if (!retval)
            continue;
        sdbd_exception(retval);

        switch (retval) {
            case -BFDEV_ESHUTDOWN:
                bfdev_log_notice("usb disconnected\n");
                sctx.verified = false;
                service_close_all(&sctx);
                retval = usb_kick(&sctx);
                if (retval < 0)
                    goto error;
                break;

            case -BFDEV_ECANCELED:
                goto finish;

            default:
                goto error;
        }
    }

finish:
    service_close_all(&sctx);
    bfdev_radix_release(&sctx.services);

    usb_close(&sctx);
    bfenv_eproc_event_remove(sctx.eproc, &sctx.usbev_out);
    bfenv_eproc_event_remove(sctx.eproc, &sctx.usbev_in);
    bfenv_iothread_destory(sctx.usbio_out, NULL, NULL);
    bfenv_iothread_destory(sctx.usbio_in, iothread_release, NULL);
    bfenv_eproc_destory(sctx.eproc);
    bfdev_log_debug("finish exit\n");

    return 0;

error:
    bfdev_log_emerg("failure exit\n");
    return 1;
}

static int
log_redirect(bfdev_log_message_t *msg, void *pdata)
{
    return write((int)(uintptr_t)pdata, msg->buff, msg->length);
}

static int
spawn_daemon(void)
{
    pid_t pid;
    int fd;

    pid = fork();
    switch (pid) {
        case -1:
            fprintf(stderr, "failed to fork daemon\n");
            return -BFDEV_EFAULT;

        case 0:
            break;

        default:
            exit(0);
    }

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        fprintf(stderr, "failed to open null\n");
        return -BFDEV_ENXIO;
    }

	if (isatty(STDIN_FILENO)) {
        if (dup2(fd, STDIN_FILENO) < 0) {
            fprintf(stderr, "failed to dup stdin\n");
            return -BFDEV_ENXIO;
        }
    }

	if (isatty(STDOUT_FILENO)) {
        if (dup2(fd, STDOUT_FILENO) < 0) {
            fprintf(stderr, "failed to dup stdout\n");
            return -BFDEV_ENXIO;
        }
    }

    if (isatty(STDERR_FILENO)) {
        if (dup2(fd, STDERR_FILENO) < 0) {
            fprintf(stderr, "failed to dup stdout\n");
            return -BFDEV_ENXIO;
        }
    }

    return pid;
}

static __bfdev_noreturn void
usage(const char *path)
{
    fprintf(stderr, "Usage: %s [option] ...\n", path);
    fprintf(stderr, "Simple Debug Bridge Daemon (SDBD) " SDBD_VERSION "\n");
    fprintf(stderr, "Hardware Acceleration: '%s'\n", hardware_accel);

    fprintf(stderr, "\n");
    fprintf(stderr, "Options:\n");
    fprintf(stderr, "  -h, --help            Display this information.\n");
    fprintf(stderr, "  -v, --version         Display version information.\n");
    fprintf(stderr, "  -d, --daemon          Run in daemon mode.\n");
    fprintf(stderr, "  -a, --authfile=PATH   Selects a public key file.\n");
    fprintf(stderr, "  -f, --logfile=PATH    Redirect logs to file.\n");
    fprintf(stderr, "  -l, --loglevel=LEVEL  Set print log level threshold.\n");
    fprintf(stderr, "  -t, --timout=SECONDS  Set service idle timeout value.\n");

    fprintf(stderr, "\n");
    fprintf(stderr, "The following optionals are for loglevel:\n");
    fprintf(stderr, "  0: Emerg    (System is unusable)\n");
    fprintf(stderr, "  1: Alert    (Action must be taken immediately)\n");
    fprintf(stderr, "  2: Crit     (Critical conditions)\n");
    fprintf(stderr, "  3: Error    (Error conditions)\n");
    fprintf(stderr, "  4: Warning  (Warning conditions)\n");
    fprintf(stderr, "  5: Notice   (Normal but significant condition)\n");
    fprintf(stderr, "  6: Info     (Informational)\n");
    fprintf(stderr, "  7: Debug    (Debug-level messages)\n");

    fprintf(stderr, "\n");
    fprintf(stderr, "For bug reporting, please visit:\n");
    fprintf(stderr, "<https://github.com/openbfdev/sdbd>\n");
    exit(1);
}

static __bfdev_noreturn void
version(void)
{
    fprintf(stderr, "sdbd version: %s\n", SDBD_INFO);
    exit(1);
}

static const struct option
options[] = {
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'v'},
    {"daemon", no_argument, NULL, 'd'},
    {"authfile", required_argument, NULL, 'a'},
    {"logfile", required_argument, NULL, 'f'},
    {"loglevel", required_argument, NULL, 'l'},
    {"timeout", required_argument, NULL, 't'},
    { }, /* NULL */
};

int
main(int argc, char *const argv[])
{
    unsigned long value;
    int arg, optidx, logfd;
    int retval;

    logfd = -1;
    sdbd_daemon = false;
    bfdev_log_default.record_level = BFDEV_LEVEL_WARNING;

    for (;;) {
        arg = getopt_long(argc, argv, "hvda:f:l:t:", options, &optidx);
        if (arg == -1)
            break;

        switch (arg) {
            case 'd':
                sdbd_daemon = true;
                break;

            case 'a':
                sdbd_auth_file = optarg;
                break;

            case 'f':
                logfd = open(optarg, O_CREAT | O_WRONLY | O_APPEND, 0644);
                if (logfd < 0) {
                    fprintf(stderr, "Failed to open log file: '%s'\n", optarg);
                    usage(argv[0]);
                }

                bfdev_log_default.write = log_redirect;
                bfdev_log_default.pdata = (void *)(uintptr_t)logfd;
                bfdev_log_color_clr(&bfdev_log_default);
                break;

            case 'l':
                value = strtoul(optarg, NULL, 10);
                if (!isdigit(*optarg) || value > BFDEV_LEVEL_DEBUG) {
                    fprintf(stderr, "Invalid loglevel value: '%s'\n", optarg);
                    usage(argv[0]);
                }
                bfdev_log_default.record_level = value;
                break;

            case 't':
                value = strtoul(optarg, NULL, 10);
                if (!isdigit(*optarg)) {
                    fprintf(stderr, "Invalid timeout value: '%s'\n", optarg);
                    usage(argv[0]);
                }
                sdbd_timeout = value * 1000;
                break;

            case 'v':
                version();

            case 'h':
                usage(argv[0]);

            default:
                fprintf(stderr, "Unknown option: %c\n", arg);
                usage(argv[0]);
        }
    }

    sdbd_shell = getenv("SHELL");
    if (!sdbd_shell)
        sdbd_shell = "/bin/sh";

    if (sdbd_daemon) {
        retval = spawn_daemon();
        if (retval < 0)
            return retval;
    }

    retval = sdbd();
    if (retval < 0)
        return retval;

    if (logfd > 0)
        close(logfd);

    return 0;
}
