/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * Copyright(c) 2025 John Sanpe <sanpeqf@gmail.com>
 */

#include <stdint.h>
#include <unistd.h>
#include <getopt.h>
#include <err.h>
#include <errno.h>
#include <signal.h>
#include <fcntl.h>
#include <pty.h>
#include <sys/wait.h>
#include <sys/eventfd.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <utime.h>
#include <linux/usb/ch9.h>
#include <linux/usb/functionfs.h>

#define MODULE_NAME "sdbd"
#define bfdev_log_fmt(fmt) MODULE_NAME ": " fmt

#include <bfdev.h>
#include <bfenv.h>

/* USB Descriptor */
#define ADB_DESC_MAGIC 1
#define ADB_STR_MAGIC 2
#define ADB_CLASS 0xff
#define ADB_SUBCLASS 0x42
#define ADB_PROTOCOL 0x1
#define ADB_INTERFACE "ADB Interface"
#define MAX_PACKET_SIZE_FS 64
#define MAX_PACKET_SIZE_HS 512

/* ADB Version */
#define ADB_VERSION 0x1000000
#define ADB_DEVICE_BANNER "device"
#define MAX_PAYLOAD 4096
#define SYNC_MAXNAME 1024

/* ADB Command */
#define PCMD_CNXN 0x4e584e43
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
#define SYNC_CMD_DONE 0x454e4f44
#define SYNC_CMD_QUIT 0x54495551

/* SDBD Configuration */
#define USB_FIFO_DEEPTH 64
#define SYNC_FIFO_DEEPTH 256
#define SERVICE_TIMEOUT (12 * 60 * 60 * 1000)
#define ASYNC_IOWAIT_TIME 1000

static bool sdbd_daemon;
static const char *sdbd_shell;

static const char *
cnxn_props[] = {
    "ro.product.name",
    "ro.product.model",
    "ro.product.device",
};

const char *
cnxn_values[] = {
    "Linux",
    "Systemd",
    "GNU",
};

struct adb_message {
    bfdev_le32 command;
    bfdev_le32 args[2];
    bfdev_le32 length;
    bfdev_le32 cksum;
    bfdev_le32 magic;
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

struct sync_dent {
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
    bfdev_le32 fs_count;
    bfdev_le32 hs_count;
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

static const struct {
    struct adb_functionfs_descs_head header;
    struct {
        struct usb_interface_descriptor intf;
        struct adb_endpoint_descriptor_no_audio source, sink;
    } __bfdev_packed fs_descs, hs_descs;
} __bfdev_packed adb_desc = {
    .header = {
        .magic = ADB_DESC_MAGIC,
        .length = sizeof(adb_desc),
        .fs_count = 3,
        .hs_count = 3,
    },
    .fs_descs = {
        .intf = {
            .bLength = sizeof(adb_desc.fs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = ADB_CLASS,
            .bInterfaceSubClass = ADB_SUBCLASS,
            .bInterfaceProtocol = ADB_PROTOCOL,
            .iInterface = 1,
        },
        .source = {
            .bLength = sizeof(adb_desc.fs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
        },
        .sink = {
            .bLength = sizeof(adb_desc.fs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_FS,
        },
    },
    .hs_descs = {
        .intf = {
            .bLength = sizeof(adb_desc.hs_descs.intf),
            .bDescriptorType = USB_DT_INTERFACE,
            .bInterfaceNumber = 0,
            .bNumEndpoints = 2,
            .bInterfaceClass = ADB_CLASS,
            .bInterfaceSubClass = ADB_SUBCLASS,
            .bInterfaceProtocol = ADB_PROTOCOL,
            .iInterface = 1,
        },
        .source = {
            .bLength = sizeof(adb_desc.hs_descs.source),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 1 | USB_DIR_OUT,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
        .sink = {
            .bLength = sizeof(adb_desc.hs_descs.sink),
            .bDescriptorType = USB_DT_ENDPOINT,
            .bEndpointAddress = 2 | USB_DIR_IN,
            .bmAttributes = USB_ENDPOINT_XFER_BULK,
            .wMaxPacketSize = MAX_PACKET_SIZE_HS,
        },
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
        .magic = ADB_STR_MAGIC,
        .length = sizeof(adb_str),
        .str_count = 1,
        .lang_count = 1,
    },
    .lang = {
        .code = 0x0409,
        .str = ADB_INTERFACE,
    },
};

struct sdbd_packet {
    uint32_t command;
    uint32_t args[2];
    uint32_t length;
    uint32_t cksum;
    uint32_t magic;
    uint8_t payload[MAX_PAYLOAD];
};

struct sdbd_service {
    struct sdbd_ctx *sctx;
    int (*write)(struct sdbd_service *service, void *data, size_t length);
    void (*close)(struct sdbd_service *service);

    uint32_t local;
    uint32_t remote;
};

struct sdbd_shell_service {
    struct sdbd_service service;
    bfenv_eproc_event_t event;
    pid_t pid;
};

struct sdbd_sync_service {
    struct sdbd_service service;
    bfenv_eproc_event_t event;

    int fd;
    bfenv_iothread_t *fileio;
    uint8_t buff[MAX_PAYLOAD];
};

struct sdbd_ctx {
    bfenv_eproc_t *eproc;
    BFDEV_DECLARE_RADIX(services, struct sdbd_service *);
    bfenv_iothread_t *usbio_in;
    bfenv_iothread_t *usbio_out;

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

static int
async_write(int fd, const void *data, size_t size)
{
    size_t count;
    ssize_t rlen;

    count = 0;
    do {
        rlen = write(fd, data, size - count);
        if (rlen > 0) {
            count += rlen;
            data += rlen;
            continue;
        }

        switch (errno) {
            case EINTR:
                break;

            case EAGAIN:
                bfdev_log_debug("async write: iowaitting...\n");
                usleep(ASYNC_IOWAIT_TIME);
                break;

            default:
                bfdev_log_crit("async write: error %d\n", errno);
                return -BFDEV_EIO;
        }
    } while (count < size);

    return -BFDEV_ENOERR;
}

static int
async_usb_write(struct sdbd_ctx *sctx, const void *data, size_t size)
{
    void *buff;
    int retval;

    /* iothread is zero copy */
    buff = bfdev_malloc(NULL, size);
    if (!buff)
        return -BFDEV_ENOMEM;
    memcpy(buff, data, size);

    for (;;) {
        retval = bfenv_iothread_write(sctx->usbio_in,
            sctx->fd_in, buff, size);
        if (retval >= 0)
            break;

        switch (retval) {
            case -BFDEV_EAGAIN:
                bfdev_log_debug("async usb write: iowaitting...\n");
                usleep(ASYNC_IOWAIT_TIME);
                break;

            default:
                bfdev_log_crit("async usb write: error %d\n", errno);
                return -BFDEV_EIO;
        }
    }

    return -BFDEV_ENOERR;
}

static int
write_packet(struct sdbd_ctx *sctx, struct sdbd_packet *packet)
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
    if (retval)
        return retval;

    if (packet->length) {
        bfdev_log_debug("usbio write: payload\n");
        retval = async_usb_write(sctx, packet->payload, packet->length);
        if (retval)
            return retval;
    }

    return -BFDEV_ENOERR;
}

static uint32_t
payload_cksum(uint8_t *payload, size_t length)
{
    uint32_t cksum;

    cksum = 0;
    while (length-- > 0)
        cksum += *payload++;

    return cksum;
}

static int
send_packet(struct sdbd_ctx *sctx, struct sdbd_packet *packet)
{
    uint32_t cksum, magic;

    cksum = payload_cksum(packet->payload, packet->length);
    magic = ~packet->command;

    packet->cksum = cksum;
    packet->magic = magic;

    return write_packet(sctx, packet);
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
    struct sdbd_packet packet;
    size_t length;

    packet.command = PCMD_CNXN;
    packet.args[0] = ADB_VERSION;
    packet.args[1] = MAX_PAYLOAD;

    length = make_connect_data((char *)packet.payload, sizeof(packet.payload));
    packet.length = length;

    bfdev_log_info("send connect\n");
    return send_packet(sctx, &packet);
}

static int
send_close(struct sdbd_ctx *sctx, uint32_t local, uint32_t remote)
{
    struct sdbd_packet packet;

    packet.command = PCMD_CLSE;
    packet.args[0] = local;
    packet.args[1] = remote;
    packet.length = 0;

    bfdev_log_info("send close: local %u remote %u\n", local, remote);
    return send_packet(sctx, &packet);
}

static int
send_okay(struct sdbd_ctx *sctx, uint32_t local, uint32_t remote)
{
    struct sdbd_packet packet;

    packet.command = PCMD_OKAY;
    packet.args[0] = local;
    packet.args[1] = remote;
    packet.length = 0;

    bfdev_log_info("send okay: local %u remote %u\n", local, remote);
    return send_packet(sctx, &packet);
}

static int
send_data(struct sdbd_ctx *sctx, uint32_t local, uint32_t remote, void *data, size_t size)
{
    struct sdbd_packet packet;

    packet.command = PCMD_WRTE;
    packet.args[0] = local;
    packet.args[1] = remote;

    packet.length = size;
    memcpy(packet.payload, data, size);

    bfdev_log_debug("send data: local %u remote %u size %lu\n",
        local, remote, size);
    return send_packet(sctx, &packet);
}

static pid_t
spawn_shell(int *amaster, const char *path, char *cmdline)
{
    pid_t pid;
    char *value;
    int retval;

    pid = forkpty(amaster, NULL, NULL, NULL);
    if (pid != 0)
        return pid;

    value = getenv("TERM");
    if (!value) {
        retval = setenv("TERM", "xterm-256color", 0);
        if (retval)
            exit(retval);
    }

    value = getenv("HOME");
    if (value) {
        retval = chdir(value);
        if (retval)
            exit(retval);
    }

    retval = execl(path, path, cmdline ? "-c" : NULL, cmdline, NULL);
    if (retval)
        exit(retval);

    /* should never come here */
    BFDEV_BUG();
}

static void
service_shell_release(struct sdbd_service *service)
{
    struct sdbd_shell_service *shell;

    shell = bfdev_container_of(service, struct sdbd_shell_service, service);
    bfenv_eproc_event_remove(service->sctx->eproc, &shell->event);
    close(shell->event.fd);

    bfdev_radix_free(&service->sctx->services, service->local);
    bfdev_free(NULL, service);
}

static int
service_shell_write(struct sdbd_service *service, void *data, size_t length)
{
    struct sdbd_shell_service *shell;

    shell = bfdev_container_of(service, struct sdbd_shell_service, service);
    return async_write(shell->event.fd, data, length);
}

static void
service_shell_close(struct sdbd_service *service)
{
    struct sdbd_shell_service *shell;

    shell = bfdev_container_of(service, struct sdbd_shell_service, service);
    kill(shell->pid, SIGKILL);
    service_shell_release(service);
}

static int
service_shell_handle(bfenv_eproc_event_t *event, void *pdata)
{
    struct sdbd_shell_service *shell;
    uint8_t buffer[MAX_PAYLOAD];
    ssize_t length;
    int retval;

    /* shell exit */
    shell = pdata;
    if (bfenv_eproc_error_test(&event->events)) {
        bfdev_log_info("shell handled: disconnected\n");
        retval = send_close(shell->service.sctx, 0, shell->service.remote);
        if (retval < 0)
            return retval;

        service_shell_close(&shell->service);
        return -BFDEV_ENOERR;
    }

    length = read(event->fd, buffer, MAX_PAYLOAD);
    if (length <= 0)
        return -BFDEV_EIO;

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

    pid = spawn_shell(&amaster, sdbd_shell, cmdline);
    if (pid < 0)
        return BFDEV_ERR_PTR(-BFDEV_EFAULT);

    shell = bfdev_zalloc(NULL, sizeof(*shell));
    if (!shell)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);

    shell->service.sctx = sctx;
    shell->service.remote = sctx->args[0];
    shell->service.local = ++sctx->sockid;
    shell->service.write = service_shell_write;
    shell->service.close = service_shell_close;
    shell->pid = pid;

    psrv = bfdev_radix_alloc(&sctx->services, sctx->sockid);
    if (!psrv)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);
    *psrv = &shell->service;

    shell->event.fd = amaster;
    shell->event.flags = BFENV_EPROC_READ;
    shell->event.func = service_shell_handle;
    shell->event.pdata = shell;

    retval = bfenv_eproc_event_add(sctx->eproc, &shell->event);
    if (retval < 0)
        return BFDEV_ERR_PTR(retval);

    return &shell->service;
}

static struct sdbd_service *
service_reboot_open(struct sdbd_ctx *sctx, char *cmdline)
{
    char buff[MAX_PAYLOAD];
    bfdev_scnprintf(buff, sizeof(buff), "reboot %s", cmdline);
    return service_shell_open(sctx, buff);
}

static struct sdbd_service *
service_remount_open(struct sdbd_ctx *sctx, char *cmdline)
{
    return service_shell_open(sctx, "mount -o remount,rw /system");
}

static void
service_sync_close(struct sdbd_service *service)
{
    struct sdbd_sync_service *sync;

    sync = bfdev_container_of(service, struct sdbd_sync_service, service);
    if (sync->fileio) {
        bfenv_eproc_event_remove(sync->service.sctx->eproc, &sync->event);
        bfenv_iothread_destory(sync->fileio);
    }

    bfdev_radix_free(&service->sctx->services, service->local);
    bfdev_free(NULL, service);
}

static int
service_sync_stat(struct sdbd_sync_service *sync, char *filename)
{
    struct sync_stat syncmsg;
	struct stat st;
    int retval;

    bzero(&syncmsg, sizeof(syncmsg));
	syncmsg.id = bfdev_cpu_to_le32(SYNC_CMD_STAT);

	if (!lstat(filename, &st)) {
		syncmsg.mode = bfdev_cpu_to_le32(st.st_mode);
		syncmsg.size = bfdev_cpu_to_le32(st.st_size);
		syncmsg.time = bfdev_cpu_to_le32(st.st_mtime);
	}

    retval = send_data(sync->service.sctx, sync->service.local,
        sync->service.remote, &syncmsg, sizeof(syncmsg));
    if (retval)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_sync_list(struct sdbd_sync_service *sync, char *filename)
{
    return -BFDEV_ENOERR;
}

static int
service_sync_send(struct sdbd_sync_service *sync, char *filename)
{
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
        bfdev_log_emerg("sync recv handled: eventfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    bfdev_log_debug("sync recv handled: pending %lu\n", count);
    BFDEV_BUG_ON(count != 1);

    deepth = bfdev_fifo_get(&sync->fileio->done_works, &request);
    BFDEV_BUG_ON(deepth != 1);

    if (request.error) {
        if (request.error == ESHUTDOWN)
            return -BFDEV_ESHUTDOWN;

        bfdev_log_err("sync recv handled: error %d\n", request.error);
        return -BFDEV_EFAULT;
    }

    switch (request.event) {
        case BFENV_IOTHREAD_EVENT_READ:
            break;

        default:
            BFDEV_BUG();
    }

    bfdev_log_debug("sync recv handled: remaining %ld\n", request.size);
    if (!request.size) {
        syncmsg.id = SYNC_CMD_DONE;
        syncmsg.size = 0;

        bfdev_log_info("shell recv handled: finish\n");
        retval = send_data(sync->service.sctx, sync->service.local,
            sync->service.remote, request.buffer, request.size);
        if (retval)
            return retval;

        send_close(sync->service.sctx, sync->service.local, sync->service.remote);
        service_sync_close(&sync->service);

        return -BFDEV_ENOERR;
    }

    syncmsg.id = SYNC_CMD_DATA;
    syncmsg.size = request.size;

    retval = send_data(sync->service.sctx, sync->service.local,
        sync->service.remote, &syncmsg, sizeof(syncmsg));
    if (retval)
        return retval;

    retval = send_data(sync->service.sctx, sync->service.local,
        sync->service.remote, request.buffer, request.size);
    if (retval)
        return retval;

    retval = bfenv_iothread_read(sync->fileio, sync->fd,
        &sync->buff, sizeof(sync->buff));
    if (retval)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_sync_recv(struct sdbd_sync_service *sync, char *filename)
{
    int retval;

    sync->fd = open(filename, O_RDONLY);
    if (sync->fd < 0)
        return -BFDEV_EACCES;

    sync->fileio = bfenv_iothread_create(NULL, SYNC_FIFO_DEEPTH,
        BFENV_IOTHREAD_FLAGS_SIGREAD);
    if (!sync->fileio)
        return -BFDEV_EFAULT;

    sync->event.fd = sync->fileio->eventfd;
    sync->event.flags = BFENV_EPROC_READ;
    sync->event.func = service_sync_recv_handle;
    sync->event.pdata = sync;

    retval = bfenv_eproc_event_add(sync->service.sctx->eproc, &sync->event);
    if (retval < 0)
        return retval;

    retval = bfenv_iothread_read(sync->fileio, sync->fd,
        &sync->buff, sizeof(sync->buff));
    if (retval)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_sync_write(struct sdbd_service *service, void *data, size_t length)
{
    struct sdbd_sync_service *sync;
    char filename[SYNC_MAXNAME + 1];
    struct sync_request *syncmsg;
    uint32_t cmd, namelen;
    int retval;

    sync = bfdev_container_of(service, struct sdbd_sync_service, service);
    if (length < sizeof(*syncmsg))
        return -BFDEV_EREMOTEIO;

    syncmsg = data;
    cmd = bfdev_le32_to_cpu(syncmsg->id);
    namelen = bfdev_le32_to_cpu(syncmsg->namelen);

    data += sizeof(*syncmsg);
    length -= sizeof(*syncmsg);

    bfdev_log_debug("sync write: remaining %u namelen %u\n", length, namelen);
    if (namelen > SYNC_MAXNAME)
        return -BFDEV_EBADMSG;

    if (length != namelen) {
        bfdev_log_warn("sync write: namelen not equal to remaining\n");
        bfdev_min_adj(namelen, length);
    }

    memcpy(filename, data, namelen);
    filename[namelen] = '\0';

    bfdev_log_notice("sync write: command %c%c%c%c filename %s\n",
        (cmd >> 0) & 0xff, (cmd >> 8) & 0xff, (cmd >> 16) & 0xff,
        (cmd >> 24) & 0xff, filename);

    switch (cmd) {
        case SYNC_CMD_STAT:
            retval = service_sync_stat(sync, filename);
            if (retval)
                return retval;
            break;

        case SYNC_CMD_LIST:
            retval = service_sync_list(sync, filename);
            if (retval)
                return retval;
            break;

        case SYNC_CMD_SEND:
            retval = service_sync_send(sync, filename);
            if (retval)
                return retval;
            break;

        case SYNC_CMD_RECV:
            retval = service_sync_recv(sync, filename);
            if (retval)
                return retval;
            break;

        case SYNC_CMD_QUIT: default:
            send_close(service->sctx, 0, service->remote);
            service_sync_close(service);
            break;
    }

    return -BFDEV_ENOERR;
}

static struct sdbd_service *
service_sync_open(struct sdbd_ctx *sctx, char *cmdline)
{
    struct sdbd_sync_service *sync;
    struct sdbd_service **psrv;

    sync = bfdev_zalloc(NULL, sizeof(*sync));
    if (!sync)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);

    sync->service.sctx = sctx;
    sync->service.remote = sctx->args[0];
    sync->service.local = ++sctx->sockid;
    sync->service.write = service_sync_write;
    sync->service.close = service_sync_close;

    psrv = bfdev_radix_alloc(&sctx->services, sctx->sockid);
    if (!psrv)
        return BFDEV_ERR_PTR(-BFDEV_ENOMEM);
    *psrv = &sync->service;

    return &sync->service;
}

static struct {
    const char *name;
    struct sdbd_service *(*open)(struct sdbd_ctx *sctx, char *cmdline);
} const
services[] = {
    {
        .name = "shell:",
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
        if (!*cmdline)
            cmdline = NULL;

        service = services[index].open(sctx, cmdline);
        if (BFDEV_IS_INVAL(service))
            return BFDEV_PTR_INVAL(service);

        retval = send_okay(sctx, service->local, service->remote);
        if (retval < 0)
            return retval;

        return -BFDEV_ENOERR;
    }

    bfdev_log_warn("service open: unsupported service\n");
    retval = send_close(sctx, 0, sctx->args[0]);
    if (retval)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_write(struct sdbd_ctx *sctx, uint8_t *payload)
{
    struct sdbd_service *service, **psrv;
    uint32_t local;
    int retval;

    local = sctx->args[1];
    psrv = bfdev_radix_find(&sctx->services, local);
    if (!psrv) {
        bfdev_log_err("service write: failed connect to %d\n", local);
        return -BFDEV_ENOERR;
    }
    service = *psrv;

    retval = service->write(service, payload, sctx->length);
    if (retval)
        return retval;

    retval = send_okay(sctx, service->local, service->remote);
    if (retval)
        return retval;

    return -BFDEV_ENOERR;
}

static int
service_close(struct sdbd_ctx *sctx)
{
    struct sdbd_service *service, **psrv;
    uint32_t local;

    local = sctx->args[1];
    psrv = bfdev_radix_find(&sctx->services, local);
    if (!psrv) {
        bfdev_log_debug("service close: already close\n");
        return -BFDEV_ENOERR;
    }

    service = *psrv;
    service->close(service);

    return -BFDEV_ENOERR;
}

static int
handle_packet(struct sdbd_ctx *sctx, uint32_t cmd, uint8_t *payload)
{
    int retval;

    bfdev_log_info("handled packet: %c%c%c%c (%u %u) length %u\n",
        (cmd >> 0) & 0xff, (cmd >> 8) & 0xff, (cmd >> 16) & 0xff,
        (cmd >> 24) & 0xff, sctx->args[0], sctx->args[1], sctx->length);
    bfdev_log_debug("packet payload: %s\n", payload);

    switch (cmd) {
        case PCMD_CNXN:
            retval = send_connect(sctx);
            if (retval)
                return retval;
            bfdev_log_notice("usb connected\n");
            break;

        case PCMD_OPEN:
            retval = service_open(sctx, (void *)payload);
            if (retval)
                return retval;
            break;

        case PCMD_CLSE:
            retval = service_close(sctx);
            if (retval)
                return retval;
            break;

        case PCMD_WRTE:
            retval = service_write(sctx, payload);
            if (retval)
                return retval;
            break;

        case PCMD_OKAY:
            /* Ignore */
            break;

        default:
            bfdev_log_warn("handled packet: unsupported command\n");
            retval = send_close(sctx, 0, sctx->args[0]);
            if (retval)
                return retval;
            break;
    }

    return -BFDEV_ENOERR;
}

static int
adb_usb_recv_handle(struct sdbd_ctx *sctx)
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
    if (sctx->command != ~sctx->magic || sctx->length > MAX_PAYLOAD) {
        bfdev_log_emerg("usb recv: packet header format error\n");
        return -BFDEV_EBADMSG;
    }

    if (sctx->length) {
        if (read(sctx->fd_out, payload, sctx->length) != sctx->length) {
            bfdev_log_emerg("usb recv: failed to get payload\n");
            return -BFDEV_EBADMSG;
        }
    }

    if (payload_cksum(payload, sctx->length) != sctx->check) {
        bfdev_log_emerg("usb recv: payload cksum error\n");
        return -BFDEV_EREMOTEIO;
    }

    payload[sctx->length] = '\0';
    retval = handle_packet(sctx, sctx->command, payload);
    if (retval)
        return retval;

    /* reregister usbio read handler */
    bfdev_log_debug("usbio read: message\n");
    retval = bfenv_iothread_read(sctx->usbio_out, sctx->fd_out,
        &sctx->msgbuff, sizeof(sctx->msgbuff));
    if (retval)
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
        bfdev_log_emerg("usb out handled: eventfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    bfdev_log_debug("usb out handled: pending %lu\n", count);
    BFDEV_BUG_ON(count != 1);

    deepth = bfdev_fifo_get(&sctx->usbio_out->done_works, &request);
    BFDEV_BUG_ON(deepth != 1);

    if (request.error) {
        if (request.error == ESHUTDOWN)
            return -BFDEV_ESHUTDOWN;

        bfdev_log_err("usb handled: error %d\n", request.error);
        return -BFDEV_EFAULT;
    }

    switch (request.event) {
        case BFENV_IOTHREAD_EVENT_READ:
            retval = adb_usb_recv_handle(sctx);
            break;

        default:
            BFDEV_BUG();
    }

    return retval;
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
        bfdev_log_emerg("usb in handled: eventfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    bfdev_log_debug("usb in handled: pending %lu\n", count);
    BFDEV_BUG_ON(count < 1);

    while (count--) {
        deepth = bfdev_fifo_get(&sctx->usbio_in->done_works, &request);
        BFDEV_BUG_ON(deepth != 1);

        if (request.error) {
            if (request.error == ESHUTDOWN)
                return -BFDEV_ESHUTDOWN;

            bfdev_log_err("usb handled: error %d\n", request.error);
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
        bfdev_log_emerg("signal handled: sigfd error %d\n", errno);
        return -BFDEV_EIO;
    }

    switch (si.ssi_signo) {
        case SIGCHLD:
            bfdev_log_debug("signal handled: release childrens\n");
            waitpid(-1, NULL, 0);
            break;

        default:
            BFDEV_BUG();
    }

    return -BFDEV_ENOERR;
}

static int
usb_init_send(int fd)
{
    if (write(fd, &adb_desc, sizeof(adb_desc)) != sizeof(adb_desc)) {
        bfdev_log_warn("send adb descriptors failed\n");
        return -BFDEV_EFAULT;
    }

    if (write(fd, &adb_str, sizeof(adb_str)) != sizeof(adb_str)) {
        bfdev_log_warn("send adb strings failed\n");
        return -BFDEV_EFAULT;
    }

    return -BFDEV_ENOERR;
}

static int
usb_init(struct sdbd_ctx *sctx)
{
    int retval;

    sctx->fd_ctr = open("/dev/usb-ffs/adb/ep0", O_RDWR);
    if (sctx->fd_ctr < 0)
        return -BFDEV_ENXIO;

    retval = usb_init_send(sctx->fd_ctr);
    if (retval)
        return retval;

    sctx->fd_out = open("/dev/usb-ffs/adb/ep1", O_RDONLY);
    if (sctx->fd_out < 0)
        return -BFDEV_ENXIO;

    sctx->fd_in = open("/dev/usb-ffs/adb/ep2", O_WRONLY);
    if (sctx->fd_in < 0)
        return -BFDEV_ENXIO;

    sctx->usbev_out.fd = sctx->usbio_out->eventfd;
    sctx->usbev_out.flags = BFENV_EPROC_READ;
    sctx->usbev_out.priority = -100;
    sctx->usbev_out.func = sdbd_usb_out_handle;
    sctx->usbev_out.pdata = sctx;

    sctx->usbev_in.fd = sctx->usbio_in->eventfd;
    sctx->usbev_in.flags = BFENV_EPROC_READ;
    sctx->usbev_in.priority = -100;
    sctx->usbev_in.func = sdbd_usb_in_handle;
    sctx->usbev_in.pdata = sctx;

    retval = bfenv_eproc_event_add(sctx->eproc, &sctx->usbev_out);
    if (retval)
        return retval;

    retval = bfenv_eproc_event_add(sctx->eproc, &sctx->usbev_in);
    if (retval)
        return retval;

    bfdev_log_debug("usbio read: message\n");
    retval = bfenv_iothread_read(sctx->usbio_out, sctx->fd_out,
        &sctx->msgbuff, sizeof(sctx->msgbuff));
    if (retval)
        return retval;

    return -BFDEV_ENOERR;
}

static int
usb_kick(struct sdbd_ctx *sctx)
{
    int retval;

    bfenv_eproc_event_remove(sctx->eproc, &sctx->usbev_out);
    bfenv_eproc_event_remove(sctx->eproc, &sctx->usbev_in);

    if ((retval = ioctl(sctx->fd_out, FUNCTIONFS_CLEAR_HALT)) ||
        (retval = ioctl(sctx->fd_in, FUNCTIONFS_CLEAR_HALT)))
        return -BFDEV_EIO;

    close(sctx->fd_ctr);
    close(sctx->fd_out);
    close(sctx->fd_in);

    bfdev_log_debug("usb kick\n");
    return usb_init(sctx);
}

static int
signal_init(struct sdbd_ctx *sctx)
{
    sigset_t mask;
    int sigfd, retval;

    sigemptyset(&mask);
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
    if (retval)
        return retval;

    return -BFDEV_ENOERR;
}

static int
sdbd(void)
{
    struct sdbd_ctx sctx;
    int retval;

    bzero(&sctx, sizeof(sctx));
    sctx.services = BFDEV_RADIX_INIT(&sctx.services, NULL);

    sctx.eproc = bfenv_eproc_create(NULL, "epoll");
    if (!sctx.eproc)
        return -BFDEV_EFAULT;

    retval = signal_init(&sctx);
    if (retval)
        return retval;

    sctx.usbio_out = bfenv_iothread_create(NULL, USB_FIFO_DEEPTH,
        BFENV_IOTHREAD_FLAGS_SIGREAD);
    if (!sctx.usbio_out)
        return -BFDEV_EFAULT;

    sctx.usbio_in = bfenv_iothread_create(NULL, USB_FIFO_DEEPTH,
        BFENV_IOTHREAD_FLAGS_SIGWRITE);
    if (!sctx.usbio_in)
        return -BFDEV_EFAULT;

    retval = usb_init(&sctx);
    if (retval)
        return retval;

    for (;;) {
        retval = bfenv_eproc_run(sctx.eproc, BFENV_TIMEOUT_MAX);
        switch (retval) {
            case -BFDEV_ESHUTDOWN:
                bfdev_log_notice("usb disconnected\n");
                retval = usb_kick(&sctx);
                if (retval)
                    goto eexit;

                break;

            default: eexit: {
                const char *einfo;

                if (!bfdev_errname(retval, &einfo))
                    einfo = "Unknow error";

                bfdev_log_emerg("exception occurred [%d]: %s\n", retval, einfo);
                exit(retval);
            }
        }
    }

    return -BFDEV_ENOERR;
}

static __bfdev_noreturn void
usage(const char *path)
{
    bfdev_log_crit("Usage: %s [option] ...\n", path);
    bfdev_log_crit("License GPLv2+: GNU GPL version 2 or later.\n");
    bfdev_log_crit("\n");

    exit(1);
}

static int
spawn_daemon(void)
{
    pid_t pid;
    int fd;

    pid = fork();
    switch (pid) {
        case -1:
            bfdev_log_alert("failed to fork daemon\n");
            return -BFDEV_EFAULT;

        case 0:
            break;

        default:
            exit(0);
    }

    fd = open("/dev/null", O_RDWR);
    if (fd < 0) {
        bfdev_log_alert("failed to open null\n");
        return -BFDEV_ENXIO;
    }

    if (dup2(fd, STDIN_FILENO) < 0) {
        bfdev_log_alert("failed to dup stdin\n");
        return -BFDEV_ENXIO;
    }

    if (dup2(fd, STDOUT_FILENO) < 0) {
        bfdev_log_alert("failed to dup stdout\n");
        return -BFDEV_ENXIO;
    }

    if (dup2(fd, STDERR_FILENO) < 0) {
        bfdev_log_alert("failed to dup stdout\n");
        return -BFDEV_ENXIO;
    }

    return pid;
}

static const struct option
options[] = {
    {"daemon", no_argument, 0, 'd'},
    {"debug", no_argument, 0, 't'},
    {"help", no_argument, 0, 'h'},
    { }, /* NULL */
};

int
main(int argc, char *const argv[])
{
    int arg, optidx;
    int retval;

    sdbd_daemon = false;
    bfdev_log_default.record_level = BFDEV_LEVEL_ERR;

    for (;;) {
        arg = getopt_long(argc, argv, "dth", options, &optidx);
        if (arg == -1)
            break;

        switch (arg) {
            case 'd':
                sdbd_daemon = true;
                break;

            case 't':
                bfdev_log_default.record_level = BFDEV_LEVEL_DEBUG;
                break;

            case 'h': default:
                bfdev_log_err("Unknown option: %c\n", arg);
                usage(argv[0]);
        }
    }

    sdbd_shell = getenv("SHELL");
    if (!sdbd_shell)
        sdbd_shell = "/bin/sh";

    if (sdbd_daemon) {
        retval = spawn_daemon();
        if (retval)
            return retval;
    }

    return sdbd();
}
