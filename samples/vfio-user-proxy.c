/*
 * Copyright (c) 2026, Red Hat Inc. All rights reserved.
 *     Author: Jesse Taube <jtaubepe@redhat.com>
 *
 *  Redistribution and use in source and binary forms, with or without
 *  modification, are permitted provided that the following conditions are met:
 *      * Redistributions of source code must retain the above copyright
 *        notice, this list of conditions and the following disclaimer.
 *      * Redistributions in binary form must reproduce the above copyright
 *        notice, this list of conditions and the following disclaimer in the
 *        documentation and/or other materials provided with the distribution.
 *      * Neither the name of Nutanix nor the names of its contributors may be
 *        used to endorse or promote products derived from this software without
 *        specific prior written permission.
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
 *   vfio-user-proxy [-vv] <socketpath> <device-bdf>
 *
 * Example:
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/e1000e/unbind
 *   echo vfio-pci > /sys/bus/pci/devices/0000:03:00.0/driver_override
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
 *   vfio-user-proxy /tmp/proxy.sock 0000:03:00.0
 *
 * Limitations:
 *   - Only INTx interrupt forwarding is implemented.  MSI/MSI-X vectors
 *     are not forwarded; extending this requires setting up per-vector
 *     eventfds and monitoring them with epoll.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <linux/vfio.h>

#include <vfn/vfio.h>
#include <vfn/pci.h>

#include "common.h"
#include "libvfio-user.h"
#include "pci_defs.h"

enum {
    POLL_VFU = 0,
    POLL_INTX,
    POLL_NR,
};

struct proxy_data {
    struct vfio_pci_device pci;
    struct vfio_region_info rom_region;
    int log_level;

    int intx_eventfd;
    vfu_ctx_t *vfu_ctx;
    struct pollfd fds[POLL_NR];
};

static const char *
log_level_str(int level)
{
    switch (level) {
    case LOG_ERR:     return "ERROR";
    case LOG_WARNING: return "WARN ";
    case LOG_INFO:    return "INFO ";
    case LOG_DEBUG:   return "DEBUG";
    default:          return "?????";
    }
}

static void
proxy_log(vfu_ctx_t *vfu_ctx UNUSED, UNUSED int level, char const *msg)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);

    if (level > p->log_level) {
        return;
    }

    fprintf(stderr, "proxy[%s]: %s\n", log_level_str(level), msg);
}

static ssize_t access_common(vfu_ctx_t *vfu_ctx, char *buf, size_t count,
		  loff_t offset, bool is_write, uint64_t region_offset,
		  const char *region_name)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t vfio_off = region_offset + offset;
    ssize_t ret;

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %s %zu bytes at %#lx (vfio_off %#lx)",
	    region_name, is_write ? "write" : "read",
	    count, (unsigned long)offset, (unsigned long)vfio_off);

    if (is_write) {
        ret = pwrite(p->pci.dev.fd, buf, count, vfio_off);
    } else {
        ret = pread(p->pci.dev.fd, buf, count, vfio_off);
    }

    if (ret < 0) {
	ret = errno;
	vfu_log(vfu_ctx, LOG_ERR, "%s %s %zu bytes at %#lx (vfio_off %#lx): %m",
	    region_name, is_write ? "write" : "read",
	    count, (unsigned long)offset, (unsigned long)vfio_off);
	errno = ret;
	return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "%s %s %zu bytes at %#lx (vfio_off %#lx) returned %d",
	    region_name, is_write ? "write" : "read",
	    count, (unsigned long)offset, (unsigned long)vfio_off, (int)ret);

    return ret;
}

#define DEFINE_BAR_CB(n) \
static ssize_t \
bar##n##_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, \
                loff_t offset, bool is_write) \
{ \
    struct proxy_data *p = vfu_get_private(vfu_ctx); \
    uint64_t region_offset = p->pci.bar_region_info[n].offset; \
    const char region_name[] = "BAR" #n; \
\
    return access_common(vfu_ctx, buf, count, offset, is_write, region_offset, region_name); \
}

DEFINE_BAR_CB(0)
DEFINE_BAR_CB(1)
DEFINE_BAR_CB(2)
DEFINE_BAR_CB(3)
DEFINE_BAR_CB(4)
DEFINE_BAR_CB(5)

static vfu_region_access_cb_t *bar_cbs[PCI_BARS_NR] = {
    bar0_access, bar1_access, bar2_access,
    bar3_access, bar4_access, bar5_access,
};

static ssize_t
cfg_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t region_offset = p->pci.config_region_info.offset;

    return access_common(vfu_ctx, buf, count, offset, is_write,
		region_offset, "config");

}

static ssize_t
rom_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t region_offset = p->rom_region.offset;

    if (is_write) {
        vfu_log(vfu_ctx, LOG_WARNING, "ROM write rejected (read-only) at %#lx+%zu",
                (unsigned long)offset, count);
        errno = EPERM;
        return -1;
    }

    return access_common(vfu_ctx, buf, count, offset, false, region_offset, "ROM");
}

static int
device_reset(vfu_ctx_t *vfu_ctx, vfu_reset_type_t type)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    int ret;

    vfu_log(vfu_ctx, LOG_INFO, "device reset requested (type=%d)", type);

    ret = vfio_reset(&p->pci.dev);
    if (ret < 0) {
        if (errno == ENOTSUP) {
            vfu_log(vfu_ctx, LOG_WARNING,
                    "device does not support reset, ignoring");
            return 0;
        }
        vfu_log(vfu_ctx, LOG_ERR, "vfio_reset: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_INFO, "device reset successful");
    return 0;
}

static int
setup_intx(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    struct vfio_irq_info irq = {
        .argsz = sizeof(irq),
        .index = VFIO_PCI_INTX_IRQ_INDEX,
    };

    if (ioctl(p->pci.dev.fd, VFIO_DEVICE_GET_IRQ_INFO, &irq) < 0) {
        vfu_log(vfu_ctx, LOG_INFO, "INTx IRQ info query failed: %m");
        return -1;
    }

    if (irq.count == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "INTx not available (count=0)");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "INTx info: count=%u flags=%#x",
            irq.count, irq.flags);

    p->intx_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    if (p->intx_eventfd < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "eventfd creation failed: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "INTx eventfd=%d", p->intx_eventfd);

    p->pci.dev.irq_info = irq;
    if (vfio_set_irq(&p->pci.dev, &p->intx_eventfd, 0, 1) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfio_set_irq failed: %m");
        close(p->intx_eventfd);
        p->intx_eventfd = -1;
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "INTx eventfd armed");

    p->fds[POLL_INTX].fd = p->intx_eventfd;
    p->fds[POLL_INTX].events = POLLIN;

    return 0;
}

static int pci_flags_to_vfu_flags(uint32_t bar_val)
{
    int vfu_flags = VFU_REGION_FLAG_RW;

    if (!(bar_val & PCI_BASE_ADDRESS_SPACE_IO)) {
        vfu_flags |= VFU_REGION_FLAG_MEM;

        if ((bar_val & PCI_BASE_ADDRESS_MEM_TYPE_MASK) ==
              PCI_BASE_ADDRESS_MEM_TYPE_64) {
            vfu_flags |= VFU_REGION_FLAG_64_BITS;
        }

        if (bar_val & PCI_BASE_ADDRESS_MEM_PREFETCH) {
            vfu_flags |= VFU_REGION_FLAG_PREFETCH;
        }
    }

    return vfu_flags;
}

static void
setup_bars(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    int ret, flags, i;
    uint32_t bar_val;

    for (i = 0; i < PCI_BARS_NR; i++) {
        if (p->pci.bar_region_info[i].size == 0) {
            vfu_log(vfu_ctx, LOG_DEBUG, "BAR%d is zero size.", i);
            continue;
        }

        if (vfio_pci_read_config(&p->pci, &bar_val, 4,
                                 PCI_BASE_ADDRESS_0 + i * 4) != 4) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to read BAR%d config: %m", i);
            continue;
        }

        flags = pci_flags_to_vfu_flags(bar_val);

        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX + i,
                               p->pci.bar_region_info[i].size, bar_cbs[i],
                               flags, NULL, 0, -1, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to setup BAR%d: %m", i);
            continue;
        }

        vfu_log(vfu_ctx, LOG_DEBUG, "BAR%d size=%#lx flags=%#x",
                i, (unsigned long)p->pci.bar_region_info[i].size, flags);

        /* 64-bit BARs span two consecutive indices; skip the upper half. */
        if (flags & VFU_REGION_FLAG_64_BITS) {
            i++;
        }
    }
}

static int
setup_pci_id(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint16_t vendor_id, device_id, subsys_vid, subsys_id;
    uint8_t class_info[3];

    if (vfio_pci_read_config(&p->pci, &vendor_id, 2, PCI_VENDOR_ID) != 2 ||
        vfio_pci_read_config(&p->pci, &device_id, 2, PCI_DEVICE_ID) != 2 ||
        vfio_pci_read_config(&p->pci, &subsys_vid, 2, PCI_SUBSYSTEM_VENDOR_ID) != 2 ||
        vfio_pci_read_config(&p->pci, &subsys_id, 2, PCI_SUBSYSTEM_ID) != 2 ||
        vfio_pci_read_config(&p->pci, class_info, 3, PCI_CLASS_PROG) != 3) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to read PCI config identity fields");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_INFO, "PCI ID [%04x:%04x] subsys [%04x:%04x] "
            "class %02x%02x%02x",
            vendor_id, device_id, subsys_vid, subsys_id,
            class_info[2], class_info[1], class_info[0]);

    vfu_pci_set_id(vfu_ctx, vendor_id, device_id, subsys_vid, subsys_id);
    vfu_pci_set_class(vfu_ctx, class_info[2], class_info[1], class_info[0]);

    return 0;
}

static int
proxy_run(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t val;
    ssize_t cnt;
    int ret;

    for (;;) {
        ret = poll(p->fds, POLL_NR, -1);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            vfu_log(vfu_ctx, LOG_ERR, "poll: %m");
            return -1;
        }

        if (p->fds[POLL_INTX].revents & POLLIN) {
            cnt = read(p->intx_eventfd, &val, sizeof(val));
            if (cnt == (ssize_t)sizeof(val)) {
                vfu_log(vfu_ctx, LOG_DEBUG,
                        "forwarding INTx (count=%lu)",
                        (unsigned long)val);
                if (vfu_irq_trigger(vfu_ctx, 0) < 0) {
                    vfu_log(vfu_ctx, LOG_ERR, "vfu_irq_trigger: %m");
                    return -1;
                }
            }
	    if (cnt < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
		vfu_log(vfu_ctx, LOG_ERR, "read INTx eventfd: %m");
		return -1;
	    }
        }

        if (p->fds[POLL_VFU].revents & POLLIN) {
            ret = vfu_run_ctx(vfu_ctx);
            if (ret < 0) {
                if (errno == EAGAIN || errno == EWOULDBLOCK) {
                    continue;
                }
                if (errno == ENOTCONN) {
                    vfu_log(vfu_ctx, LOG_INFO, "client disconnected");
                    return 0;
                }
                vfu_log(vfu_ctx, LOG_ERR, "vfu_run_ctx: %m");
                return -1;
            }
        }

        if (p->fds[POLL_VFU].revents & (POLLHUP | POLLERR)) {
            vfu_log(vfu_ctx, LOG_INFO, "poll fd error/hangup");
            return 0;
        }
    }
}

static void setup_rom_region(struct proxy_data *p) {
    memset(&p->rom_region, 0, sizeof(p->rom_region));
    p->rom_region.argsz = sizeof(p->rom_region);
    p->rom_region.index = VFIO_PCI_ROM_REGION_INDEX;

    if (ioctl(p->pci.dev.fd, VFIO_DEVICE_GET_REGION_INFO,
              &p->rom_region) < 0) {
        vfu_log(p->vfu_ctx, LOG_DEBUG, "ROM region not available: %m");
        memset(&p->rom_region, 0, sizeof(p->rom_region));
    }
}

static int
setup_device(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    int ret;

    setup_rom_region(p);

    if (p->rom_region.size > 0) {
        ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_ROM_REGION_IDX,
                               p->rom_region.size,
                               &rom_access, VFU_REGION_FLAG_READ,
                               NULL, 0, -1, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_WARNING, "ROM region setup failed: %m");
        }
    }

    ret = vfu_setup_region(vfu_ctx, VFU_PCI_DEV_CFG_REGION_IDX, 0,
                           &cfg_access,
                           VFU_REGION_FLAG_RW | VFU_REGION_FLAG_ALWAYS_CB,
                           NULL, 0, -1, 0);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "config region setup: %m");
        return -1;
    }

    ret = vfu_setup_device_reset_cb(vfu_ctx, &device_reset);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_setup_device_reset_cb: %m");
        return -1;
    }

    ret = vfu_setup_device_nr_irqs(vfu_ctx, VFU_DEV_INTX_IRQ, 1);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_setup_device_nr_irqs: %m");
        return -1;
    }

    if (setup_intx(vfu_ctx) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "INTx forwarding enabled");
    } else {
        vfu_log(vfu_ctx, LOG_INFO, "INTx forwarding not available");
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "realizing context");
    ret = vfu_realize_ctx(vfu_ctx);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_realize_ctx: %m");
        return -1;
    }
    vfu_log(vfu_ctx, LOG_INFO, "context realized");

    vfu_log(vfu_ctx, LOG_DEBUG, "waiting for client connection");
    ret = vfu_attach_ctx(vfu_ctx);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_attach_ctx: %m");
        return -1;
    }
    vfu_log(vfu_ctx, LOG_INFO, "client connected");

    p->fds[POLL_VFU].fd = vfu_get_poll_fd(vfu_ctx);
    p->fds[POLL_VFU].events = POLLIN;

    return 0;
}

struct proxy_opts {
    const char *sock_path;
    const char *bdf;
    int log_level;
};

static void __attribute__((noreturn))
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-vv] <socketpath> <device-bdf>\n",
            prog);
    exit(EXIT_FAILURE);
}

static struct proxy_opts
parse_args(int argc, char *argv[])
{
    int opt;
    struct proxy_opts opts = {
        .log_level = LOG_ERR,
    };

    while ((opt = getopt(argc, argv, "v")) != -1) {
        switch (opt) {
        case 'v':
            if (opts.log_level < LOG_DEBUG) {
                opts.log_level++;
            }
            break;
        default:
            usage(argv[0]);
        }
    }

    if (argc - optind < 2) {
        usage(argv[0]);
    }

    opts.sock_path = argv[optind];
    opts.bdf = argv[optind + 1];
    return opts;
}

int
main(int argc, char *argv[])
{
    int ret = -1;
    struct proxy_opts opts;
    vfu_ctx_t *vfu_ctx;
    struct proxy_data proxy = {
        .intx_eventfd = -1,
        .log_level = LOG_ERR,
        .fds = {
            [POLL_INTX] = { .fd = -1 },
        },
    };

    opts = parse_args(argc, argv);
    proxy.log_level = opts.log_level;

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, opts.sock_path,
                             LIBVFIO_USER_FLAG_ATTACH_NB, &proxy,
                             VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL) {
        err(EXIT_FAILURE, "vfu_create_ctx");
    }

    proxy.vfu_ctx = vfu_ctx;

    ret = vfu_setup_log(vfu_ctx, proxy_log, proxy.log_level);
    if (ret < 0) {
        warn("vfu_setup_log");
        goto cleanup_vfu;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "creating vfu context on %s", opts.sock_path);

    ret = vfio_pci_open(&proxy.pci, opts.bdf);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfio_pci_open(%s): %m", opts.bdf);
        goto cleanup_vfu;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "device %s opened via libvfn (fd=%d)",
            opts.bdf, proxy.pci.dev.fd);

    ret = vfu_pci_init(vfu_ctx, VFU_PCI_TYPE_CONVENTIONAL,
                       PCI_HEADER_TYPE_NORMAL, 0);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_pci_init: %m");
        goto cleanup;
    }

    ret = setup_pci_id(vfu_ctx);
    if (ret < 0) {
        goto cleanup;
    }

    setup_bars(vfu_ctx);

    ret = setup_device(vfu_ctx);
    if (ret < 0) {
        goto cleanup;
    }

    vfu_log(vfu_ctx, LOG_INFO, "serving %s on %s", opts.bdf, opts.sock_path);

    ret = proxy_run(vfu_ctx);
    vfu_log(vfu_ctx, LOG_DEBUG, "main loop exited (ret=%d)", ret);

cleanup:
    if (proxy.intx_eventfd >= 0)
        close(proxy.intx_eventfd);

    vfu_log(vfu_ctx, LOG_DEBUG, "cleaning up vfio context");
    vfio_pci_close(&proxy.pci);

cleanup_vfu:
    vfu_log(vfu_ctx, LOG_DEBUG, "cleaning up vfu context");
    vfu_destroy_ctx(vfu_ctx);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
