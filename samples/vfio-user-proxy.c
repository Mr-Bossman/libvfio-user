/*
 * vfio-user proxy: exposes a kernel VFIO device as a vfio-user server.
 *
 * Opens a real PCI device via the kernel VFIO interface and proxies all
 * region accesses (config space, BARs, ROM) and INTx interrupts over a
 * vfio-user socket so that a vfio-user client (e.g. QEMU) can drive the
 * physical device.
 *
 * The device must be bound to vfio-pci before running this program.
 *
 * Usage:
 *   vfio-user-proxy [-v] <socketpath> <group-number> <device-bdf>
 *
 * Example:
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/e1000e/unbind
 *   echo vfio-pci > /sys/bus/pci/devices/0000:03:00.0/driver_override
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
 *   vfio-user-proxy /tmp/proxy.sock 42 0000:03:00.0
 *
 * Limitations:
 *   - Only INTx interrupt forwarding is implemented.  MSI/MSI-X vectors
 *     are not forwarded; extending this requires setting up per-vector
 *     eventfds and monitoring them with epoll.
 *
 * Copyright (c) 2024 Jesse Taube. All rights reserved.
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 *  AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL <COPYRIGHT HOLDER> BE LIABLE FOR ANY
 *  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 *  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 *  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 *  CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 *  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 *  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/vfio.h>

#include "common.h"
#include "libvfio-user.h"

#define MAX_BARS 6

struct proxy_data {
    int container_fd;
    int group_fd;
    int device_fd;
    bool supports_reset;

    struct {
        uint64_t size;
        uint64_t offset;
        uint32_t flags;
    } regions[VFIO_PCI_NUM_REGIONS];

    int intx_eventfd;
    pthread_t irq_thread;
    bool irq_thread_running;
    vfu_ctx_t *vfu_ctx;
};

static void
proxy_log(vfu_ctx_t *vfu_ctx UNUSED, UNUSED int level, char const *msg)
{
    fprintf(stderr, "proxy: %s\n", msg);
}

static ssize_t
bar_access_common(vfu_ctx_t *vfu_ctx, int bar_idx, char *buf, size_t count,
                  loff_t offset, bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t vfio_off = p->regions[bar_idx].offset + offset;
    ssize_t ret;

    if (is_write) {
        ret = pwrite(p->device_fd, buf, count, vfio_off);
    } else {
        ret = pread(p->device_fd, buf, count, vfio_off);
    }

    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "BAR%d %s at %#lx: %m",
                bar_idx, is_write ? "write" : "read",
                (unsigned long)offset);
        return -1;
    }

    return ret;
}

#define DEFINE_BAR_CB(n) \
static ssize_t \
bar##n##_access(vfu_ctx_t *ctx, char *buf, size_t count, \
                loff_t offset, bool is_write) \
{ \
    return bar_access_common(ctx, n, buf, count, offset, is_write); \
}

DEFINE_BAR_CB(0)
DEFINE_BAR_CB(1)
DEFINE_BAR_CB(2)
DEFINE_BAR_CB(3)
DEFINE_BAR_CB(4)
DEFINE_BAR_CB(5)

static vfu_region_access_cb_t *bar_cbs[MAX_BARS] = {
    bar0_access, bar1_access, bar2_access,
    bar3_access, bar4_access, bar5_access,
};

static ssize_t
cfg_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t vfio_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset +
                         offset;
    ssize_t ret;

    if (is_write) {
        ret = pwrite(p->device_fd, buf, count, vfio_off);
    } else {
        ret = pread(p->device_fd, buf, count, vfio_off);
    }

    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "config %s at %#lx: %m",
                is_write ? "write" : "read", (unsigned long)offset);
        return -1;
    }

    return ret;
}

static ssize_t
rom_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t vfio_off = p->regions[VFIO_PCI_ROM_REGION_INDEX].offset + offset;
    ssize_t ret;

    if (is_write) {
        errno = EPERM;
        return -1;
    }

    ret = pread(p->device_fd, buf, count, vfio_off);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "ROM read at %#lx: %m",
                (unsigned long)offset);
        return -1;
    }

    return ret;
}

static void *
irq_thread_fn(void *arg)
{
    struct proxy_data *p = arg;
    uint64_t val;

    while (p->irq_thread_running) {
        ssize_t ret = read(p->intx_eventfd, &val, sizeof(val));
        if (ret != (ssize_t)sizeof(val)) {
            if (errno == EINTR)
                continue;
            break;
        }
        vfu_irq_trigger(p->vfu_ctx, 0);
    }

    return NULL;
}

static int
device_reset(vfu_ctx_t *vfu_ctx, vfu_reset_type_t type UNUSED)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);

    if (!p->supports_reset)
        return 0;

    if (ioctl(p->device_fd, VFIO_DEVICE_RESET) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_DEVICE_RESET: %m");
        return -1;
    }

    return 0;
}

static void
setup_vfio(struct proxy_data *p, int group_num, const char *bdf)
{
    char path[64];
    struct vfio_group_status gs = { .argsz = sizeof(gs) };
    struct vfio_device_info di = { .argsz = sizeof(di) };

    p->container_fd = open("/dev/vfio/vfio", O_RDWR);
    if (p->container_fd < 0)
        err(EXIT_FAILURE, "/dev/vfio/vfio");

    if (ioctl(p->container_fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION)
        errx(EXIT_FAILURE, "VFIO API version mismatch");

    snprintf(path, sizeof(path), "/dev/vfio/%d", group_num);
    p->group_fd = open(path, O_RDWR);
    if (p->group_fd < 0) {
        snprintf(path, sizeof(path), "/dev/vfio/noiommu-%d", group_num);
        p->group_fd = open(path, O_RDWR);
        if (p->group_fd < 0)
            err(EXIT_FAILURE, "VFIO group %d", group_num);
    }

    if (ioctl(p->group_fd, VFIO_GROUP_GET_STATUS, &gs) < 0)
        err(EXIT_FAILURE, "VFIO_GROUP_GET_STATUS");

    if (!(gs.flags & VFIO_GROUP_FLAGS_VIABLE))
        errx(EXIT_FAILURE,
             "VFIO group not viable (all devices bound to vfio-pci?)");

    if (ioctl(p->group_fd, VFIO_GROUP_SET_CONTAINER, &p->container_fd) < 0)
        err(EXIT_FAILURE, "VFIO_GROUP_SET_CONTAINER");

    if (ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU) < 0 &&
        ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) < 0 &&
        ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_NOIOMMU_IOMMU) < 0)
        err(EXIT_FAILURE, "VFIO_SET_IOMMU");

    p->device_fd = ioctl(p->group_fd, VFIO_GROUP_GET_DEVICE_FD, bdf);
    if (p->device_fd < 0)
        err(EXIT_FAILURE, "VFIO_GROUP_GET_DEVICE_FD(%s)", bdf);

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_INFO, &di) < 0)
        err(EXIT_FAILURE, "VFIO_DEVICE_GET_INFO");

    if (!(di.flags & VFIO_DEVICE_FLAGS_PCI))
        errx(EXIT_FAILURE, "%s is not a PCI device", bdf);

    p->supports_reset = !!(di.flags & VFIO_DEVICE_FLAGS_RESET);

    for (uint32_t i = 0; i < di.num_regions && i < VFIO_PCI_NUM_REGIONS; i++) {
        struct vfio_region_info ri = {
            .argsz = sizeof(ri),
            .index = i,
        };
        if (ioctl(p->device_fd, VFIO_DEVICE_GET_REGION_INFO, &ri) == 0) {
            p->regions[i].size = ri.size;
            p->regions[i].offset = ri.offset;
            p->regions[i].flags = ri.flags;
        }
    }
}

static int
setup_intx(struct proxy_data *p)
{
    struct vfio_irq_info irq = {
        .argsz = sizeof(irq),
        .index = VFIO_PCI_INTX_IRQ_INDEX,
    };

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq) < 0 ||
        irq.count == 0)
        return -1;

    p->intx_eventfd = eventfd(0, EFD_CLOEXEC);
    if (p->intx_eventfd < 0)
        return -1;

    struct {
        struct vfio_irq_set hdr;
        int32_t fd;
    } irq_set = {
        .hdr = {
            .argsz = sizeof(irq_set),
            .flags = VFIO_IRQ_SET_DATA_EVENTFD |
                     VFIO_IRQ_SET_ACTION_TRIGGER,
            .index = VFIO_PCI_INTX_IRQ_INDEX,
            .start = 0,
            .count = 1,
        },
        .fd = p->intx_eventfd,
    };

    if (ioctl(p->device_fd, VFIO_DEVICE_SET_IRQS, &irq_set) < 0) {
        close(p->intx_eventfd);
        p->intx_eventfd = -1;
        return -1;
    }

    return 0;
}

int
main(int argc, char *argv[])
{
    int ret, opt;
    bool verbose = false;
    struct proxy_data proxy = {
        .container_fd = -1,
        .group_fd = -1,
        .device_fd = -1,
        .intx_eventfd = -1,
    };

    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
        case 'v':
            verbose = true;
            break;
        default:
            goto usage;
        }
    }

    if (argc - optind < 3) {
usage:
        fprintf(stderr,
                "Usage: %s [-v] <socketpath> <group-number> <device-bdf>\n",
                argv[0]);
        exit(EXIT_FAILURE);
    }

    const char *sock_path = argv[optind];
    int group_num = atoi(argv[optind + 1]);
    const char *bdf = argv[optind + 2];

    setup_vfio(&proxy, group_num, bdf);

    if (proxy.regions[VFIO_PCI_CONFIG_REGION_INDEX].size == 0)
        errx(EXIT_FAILURE, "%s: no config region", bdf);

    uint64_t cfg_off = proxy.regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
    uint16_t vendor_id, device_id, subsys_vid, subsys_id;
    uint8_t class_info[3];

    pread(proxy.device_fd, &vendor_id, 2, cfg_off + PCI_VENDOR_ID);
    pread(proxy.device_fd, &device_id, 2, cfg_off + PCI_DEVICE_ID);
    pread(proxy.device_fd, &subsys_vid, 2, cfg_off + PCI_SUBSYSTEM_VENDOR_ID);
    pread(proxy.device_fd, &subsys_id, 2, cfg_off + PCI_SUBSYSTEM_ID);
    pread(proxy.device_fd, class_info, 3, cfg_off + PCI_CLASS_PROG);

    fprintf(stderr, "proxy: %s [%04x:%04x] class %02x%02x%02x\n",
            bdf, vendor_id, device_id,
            class_info[2], class_info[1], class_info[0]);

    vfu_ctx_t *vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, sock_path, 0, &proxy,
                                        VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL)
        err(EXIT_FAILURE, "vfu_create_ctx");

    proxy.vfu_ctx = vfu_ctx;

    ret = vfu_setup_log(vfu_ctx, proxy_log, verbose ? LOG_DEBUG : LOG_ERR);
    if (ret < 0)
        err(EXIT_FAILURE, "vfu_setup_log");

    ret = vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_CONVENTIONAL,
                       PCI_HEADER_TYPE_NORMAL, 0);
    if (ret < 0)
        err(EXIT_FAILURE, "vfu_pci_init");

    vfu_pci_set_id(vfu_ctx, vendor_id, device_id, subsys_vid, subsys_id);
    vfu_pci_set_class(vfu_ctx, class_info[2], class_info[1], class_info[0]);

    for (int i = 0; i < MAX_BARS; i++) {
        if (proxy.regions[i].size == 0)
            continue;

        int flags = VFU_REGION_FLAG_RW;
        uint32_t bar_val;

        pread(proxy.device_fd, &bar_val, 4,
              cfg_off + PCI_BASE_ADDRESS_0 + i * 4);

        if (!(bar_val & PCI_BASE_ADDRESS_SPACE_IO)) {
            flags |= VFU_REGION_FLAG_MEM;

            if ((bar_val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
                PCI_BASE_ADDRESS_MEM_TYPE_64)
                flags |= VFU_REGION_FLAG_64_BITS;

            if (bar_val & PCI_BASE_ADDRESS_MEM_PREFETCH)
                flags |= VFU_REGION_FLAG_PREFETCH;
        }

        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX + i,
                               proxy.regions[i].size, bar_cbs[i], flags,
                               NULL, 0, -1, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to setup BAR%d: %m", i);
            continue;
        }

        if (verbose) {
            fprintf(stderr, "proxy: BAR%d size=%#lx flags=%#x\n",
                    i, (unsigned long)proxy.regions[i].size, flags);
        }
    }

    if (proxy.regions[VFIO_PCI_ROM_REGION_INDEX].size > 0) {
        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_ROM_REGION_IDX,
                               proxy.regions[VFIO_PCI_ROM_REGION_INDEX].size,
                               &rom_access, VFU_REGION_FLAG_READ,
                               NULL, 0, -1, 0);
        if (ret < 0 && verbose)
            fprintf(stderr, "proxy: ROM region setup failed: %m\n");
    }

    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_CFG_REGION_IDX, 0,
                           &cfg_access,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_ALWAYS_CB,
                           NULL, 0, -1, 0);
    if (ret < 0)
        err(EXIT_FAILURE, "config region setup");

    ret = vfu_setup_device_reset_cb(vfu_ctx, &device_reset);
    if (ret < 0)
        err(EXIT_FAILURE, "vfu_setup_device_reset_cb");

    ret = vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_INTX_IRQ, 1);
    if (ret < 0)
        err(EXIT_FAILURE, "vfu_setup_device_nr_irqs");

    if (setup_intx(&proxy) == 0 && verbose)
        fprintf(stderr, "proxy: INTx forwarding enabled\n");

    ret = vfu_realize_ctx(vfu_ctx);
    if (ret < 0)
        err(EXIT_FAILURE, "vfu_realize_ctx");

    ret = vfu_attach_ctx(vfu_ctx);
    if (ret < 0)
        err(EXIT_FAILURE, "vfu_attach_ctx");

    if (proxy.intx_eventfd >= 0) {
        proxy.irq_thread_running = true;
        ret = pthread_create(&proxy.irq_thread, NULL, irq_thread_fn, &proxy);
        if (ret != 0) {
            errno = ret;
            err(EXIT_FAILURE, "pthread_create");
        }
    }

    fprintf(stderr, "proxy: serving %s on %s\n", bdf, sock_path);

    do {
        ret = vfu_run_ctx(vfu_ctx);
        if (ret == -1 && errno == EINTR)
            ret = 0;
    } while (ret == 0);

    proxy.irq_thread_running = false;
    if (proxy.intx_eventfd >= 0) {
        close(proxy.intx_eventfd);
        pthread_join(proxy.irq_thread, NULL);
    }

    vfu_destroy_ctx(vfu_ctx);
    close_safely(&proxy.device_fd);
    close_safely(&proxy.group_fd);
    close_safely(&proxy.container_fd);

    return EXIT_SUCCESS;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
