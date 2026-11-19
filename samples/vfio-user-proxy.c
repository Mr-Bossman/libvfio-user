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
 *   vfio-user-proxy [-vv] [-R] <socketpath> <device-bdf>
 *     -R  disable ROM BAR
 * Example:
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/e1000e/unbind
 *   echo vfio-pci > /sys/bus/pci/devices/0000:03:00.0/driver_override
 *   echo 0000:03:00.0 > /sys/bus/pci/drivers/vfio-pci/bind
 *   vfio-user-proxy /tmp/proxy.sock 0000:03:00.0
 *
 * Interrupt forwarding:
 *   All IRQ types supported by the device (INTx, MSI, MSI-X, ERR, REQ)
 *   are registered and armed with per-vector eventfds, monitored via poll().
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <poll.h>
#include <stdbool.h>
#include <sys/ioctl.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <linux/pci_regs.h>
#include <linux/vfio.h>

#include "common.h"
#include "libvfio-user.h"
#include "pci_defs.h"

#define MAX_DMA_BOUNCES 64

struct dma_bounce {
    void *iova_base;
    size_t size;
    void *bounce;
    int fd;
    bool active;
};

struct poll_irq_entry {
    int type;
    int vec;
};

enum {
    POLL_VFU = 0,
    POLL_IRQ_START,
};

struct proxy_data {
    int container_fd;
    int group_fd;
    int device_fd;
    bool supports_reset;
    int log_level;

    struct {
        uint64_t size;
        uint64_t offset;
        uint32_t flags;
    } regions[VFIO_PCI_NUM_REGIONS];

    struct dma_bounce dma_bounces[MAX_DMA_BOUNCES];

    void *reg_mmap[VFIO_PCI_NUM_REGIONS];
    int reg_memfd[VFIO_PCI_NUM_REGIONS];

    struct {
        uint32_t count;
        int *efds;
    } irqs[VFU_DEV_NUM_IRQS];

    struct pollfd *fds;
    struct poll_irq_entry *irq_map;
    int nfds;

    bool no_rom;
    vfu_ctx_t *vfu_ctx;
    uint8_t msix_cap_off;
    uint8_t msi_cap_off;
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

static void sync_dma_from_guest(vfu_ctx_t *vfu_ctx);
static void sync_dma_to_guest(vfu_ctx_t *vfu_ctx);

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
        ret = pwrite(p->device_fd, buf, count, vfio_off);
    } else {
        ret = pread(p->device_fd, buf, count, vfio_off);
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

static int
setup_region_memfd(vfu_ctx_t *vfu_ctx, int region_idx, size_t size,
                   vfu_region_access_cb_t *cb, int flags)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    int tmpfd, ret;
    void *map;
    struct iovec mmap_area = {
        .iov_base = 0,
        .iov_len = size,
    };

    tmpfd = memfd_create("vfio-proxy-region", MFD_CLOEXEC);
    if (tmpfd < 0 || ftruncate(tmpfd, size) < 0) {
        vfu_log(vfu_ctx, LOG_ERR,
                "region %d: memfd_create/ftruncate failed: %m", region_idx);
        if (tmpfd >= 0) {
            close(tmpfd);
        }
        return vfu_setup_region(vfu_ctx, region_idx, size, cb, flags,
                                NULL, 0, -1, 0);
    }

    map = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, tmpfd, 0);
    if (map == MAP_FAILED) {
        vfu_log(vfu_ctx, LOG_ERR,
                "region %d: mmap failed: %m", region_idx);
        close(tmpfd);
        return vfu_setup_region(vfu_ctx, region_idx, size, cb, flags,
                                NULL, 0, -1, 0);
    }

    /* Find the VFIO region index for tracking. */
    int vfio_idx = -1;
    if (region_idx >= VFU_PCI_DEV_BAR0_REGION_IDX &&
        region_idx <= VFU_PCI_DEV_BAR5_REGION_IDX) {
        vfio_idx = VFIO_PCI_BAR0_REGION_INDEX +
                   (region_idx - VFU_PCI_DEV_BAR0_REGION_IDX);
    } else if (region_idx == VFU_PCI_DEV_ROM_REGION_IDX) {
        vfio_idx = VFIO_PCI_ROM_REGION_INDEX;
    } else if (region_idx == VFU_PCI_DEV_CFG_REGION_IDX) {
        vfio_idx = VFIO_PCI_CONFIG_REGION_INDEX;
    }

    if (vfio_idx >= 0 && vfio_idx < VFIO_PCI_NUM_REGIONS) {
        p->reg_mmap[vfio_idx] = map;
        p->reg_memfd[vfio_idx] = tmpfd;
    }

    ret = vfu_setup_region(vfu_ctx, region_idx, size, cb, flags,
                           &mmap_area, 1, tmpfd, 0);

    vfu_log(vfu_ctx, LOG_DEBUG,
            "region %d: size=%#lx memfd=%d mmap=%p",
            region_idx, (unsigned long)size, tmpfd, map);

    return ret;
}

#define DEFINE_BAR_CB(n) \
static ssize_t \
bar##n##_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, \
                loff_t offset, bool is_write) \
{ \
    struct proxy_data *p = vfu_get_private(vfu_ctx); \
    uint64_t region_offset = p->regions[VFIO_PCI_BAR0_REGION_INDEX + n].offset; \
    const char region_name[] = "BAR" #n; \
    int vfio_idx = VFIO_PCI_BAR0_REGION_INDEX + n; \
    ssize_t ret; \
\
    if (is_write && p->reg_mmap[vfio_idx] != NULL) { \
        memcpy((char *)p->reg_mmap[vfio_idx] + offset, buf, count); \
    } \
    ret = access_common(vfu_ctx, buf, count, offset, is_write, region_offset, region_name); \
    if (ret > 0 && !is_write && p->reg_mmap[vfio_idx] != NULL) { \
        memcpy((char *)p->reg_mmap[vfio_idx] + offset, buf, ret); \
    } \
    return ret; \
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

static int arm_irq_type(vfu_ctx_t *vfu_ctx, int type);
static int build_poll_fds(vfu_ctx_t *vfu_ctx);

static ssize_t
cfg_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t region_offset = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
    ssize_t ret;

    /*
     * Keep MMIO, PIO, and bus-master enabled on the real device regardless
     * of what the guest writes.  In normal VFIO passthrough the kernel
     * driver protects these bits; with ALWAYS_CB we must do it ourselves.
     */
    if (is_write && offset <= PCI_COMMAND &&
        (offset + (loff_t)count) > PCI_COMMAND) {
        size_t cmd_byte = PCI_COMMAND - offset;
        buf[cmd_byte] |= PCI_COMMAND_IO | PCI_COMMAND_MEMORY |
                         PCI_COMMAND_MASTER;
    }

    ret = access_common(vfu_ctx, buf, count, offset, is_write,
                region_offset, "config");

    if (is_write && ret > 0) {
        loff_t end = offset + count;

        if (p->msix_cap_off != 0) {
            loff_t ctrl_off = p->msix_cap_off + PCI_MSIX_FLAGS;
            if (offset <= ctrl_off && end > ctrl_off) {
                uint16_t ctrl;
                uint64_t cfg_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
                if (pread(p->device_fd, &ctrl, 2, cfg_off + ctrl_off) == 2) {
                    vfu_log(vfu_ctx, LOG_INFO,
                            "MSI-X control write: ctrl=%#x enable=%d",
                            ctrl, !!(ctrl & PCI_MSIX_FLAGS_ENABLE));
                    if (ctrl & PCI_MSIX_FLAGS_ENABLE) {
                        vfu_log(vfu_ctx, LOG_INFO,
                                "MSI-X enabled, arming eventfds");
                        arm_irq_type(vfu_ctx, VFIO_PCI_MSIX_IRQ_INDEX);
                        build_poll_fds(vfu_ctx);
                    }
                }
            }
        }

        if (p->msi_cap_off != 0) {
            loff_t ctrl_off = p->msi_cap_off + PCI_MSI_FLAGS;
            if (offset <= ctrl_off && end > ctrl_off) {
                uint16_t ctrl;
                uint64_t cfg_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
                if (pread(p->device_fd, &ctrl, 2, cfg_off + ctrl_off) == 2) {
                    vfu_log(vfu_ctx, LOG_INFO,
                            "MSI control write: ctrl=%#x enable=%d",
                            ctrl, !!(ctrl & PCI_MSI_FLAGS_ENABLE));
                    if (ctrl & PCI_MSI_FLAGS_ENABLE) {
                        vfu_log(vfu_ctx, LOG_INFO,
                                "MSI enabled, arming eventfds");
                        arm_irq_type(vfu_ctx, VFIO_PCI_MSI_IRQ_INDEX);
                        build_poll_fds(vfu_ctx);
                    }
                }
            }
        }
    }

    return ret;
}

static ssize_t
rom_access(vfu_ctx_t *vfu_ctx, char *buf, size_t count, loff_t offset,
           bool is_write)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t region_offset = p->regions[VFIO_PCI_ROM_REGION_INDEX].offset;

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

    vfu_log(vfu_ctx, LOG_INFO, "device reset requested (type=%d)", type);

    if (!p->supports_reset) {
        vfu_log(vfu_ctx, LOG_WARNING, "device does not support reset, ignoring");
        return 0;
    }

    if (ioctl(p->device_fd, VFIO_DEVICE_RESET) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_DEVICE_RESET: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_INFO, "device reset successful");
    return 0;
}

static void
dma_register(vfu_ctx_t *vfu_ctx, vfu_dma_info_t *info)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    size_t size = info->iova.iov_len;
    struct vfio_iommu_type1_dma_map dma_map = {
        .argsz = sizeof(dma_map),
        .iova = (uintptr_t)info->iova.iov_base,
        .size = size,
    };
    int idx, memfd;
    void *bounce;

    if (info->prot & PROT_READ) {
        dma_map.flags |= VFIO_DMA_MAP_FLAG_READ;
    }
    if (info->prot & PROT_WRITE) {
        dma_map.flags |= VFIO_DMA_MAP_FLAG_WRITE;
    }

    for (idx = 0; idx < MAX_DMA_BOUNCES; idx++) {
        if (!p->dma_bounces[idx].active) {
            break;
        }
    }
    if (idx >= MAX_DMA_BOUNCES) {
        vfu_log(vfu_ctx, LOG_ERR,
                "DMA bounce slots full, cannot map iova=%#lx",
                (unsigned long)dma_map.iova);
        return;
    }

    memfd = memfd_create("vfio-proxy-dma", MFD_CLOEXEC);
    if (memfd < 0 || ftruncate(memfd, size) < 0) {
        vfu_log(vfu_ctx, LOG_ERR,
                "DMA bounce memfd failed: %m (iova=%#lx size=%#lx)",
                (unsigned long)dma_map.iova, (unsigned long)size);
        if (memfd >= 0) {
            close(memfd);
        }
        return;
    }

    bounce = mmap(NULL, size, PROT_READ | PROT_WRITE, MAP_SHARED, memfd, 0);
    if (bounce == MAP_FAILED) {
        vfu_log(vfu_ctx, LOG_ERR,
                "DMA bounce mmap failed: %m (iova=%#lx size=%#lx)",
                (unsigned long)dma_map.iova, (unsigned long)size);
        close(memfd);
        return;
    }

    dma_map.vaddr = (uintptr_t)bounce;

    if (ioctl(p->container_fd, VFIO_IOMMU_MAP_DMA, &dma_map) < 0) {
        vfu_log(vfu_ctx, LOG_ERR,
                "VFIO_IOMMU_MAP_DMA failed: %m (iova=%#lx size=%#lx vaddr=%#lx)",
                (unsigned long)dma_map.iova, (unsigned long)size,
                (unsigned long)dma_map.vaddr);
        munmap(bounce, size);
        close(memfd);
        return;
    }

    p->dma_bounces[idx].iova_base = info->iova.iov_base;
    p->dma_bounces[idx].size = size;
    p->dma_bounces[idx].bounce = bounce;
    p->dma_bounces[idx].fd = memfd;
    p->dma_bounces[idx].active = true;

    vfu_log(vfu_ctx, LOG_INFO,
            "DMA bounce iova=%#lx size=%#lx bounce=%p memfd=%d",
            (unsigned long)dma_map.iova, (unsigned long)size, bounce, memfd);
}

static void
dma_unregister(vfu_ctx_t *vfu_ctx, vfu_dma_info_t *info)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    struct vfio_iommu_type1_dma_unmap dma_unmap = {
        .argsz = sizeof(dma_unmap),
        .iova = (uintptr_t)info->iova.iov_base,
        .size = info->iova.iov_len,
    };
    int idx;

    vfu_log(vfu_ctx, LOG_INFO, "DMA unmap iova=%#lx size=%#lx",
            (unsigned long)dma_unmap.iova, (unsigned long)dma_unmap.size);

    if (ioctl(p->container_fd, VFIO_IOMMU_UNMAP_DMA, &dma_unmap) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_IOMMU_UNMAP_DMA failed: %m");
    }

    for (idx = 0; idx < MAX_DMA_BOUNCES; idx++) {
        if (p->dma_bounces[idx].active &&
            p->dma_bounces[idx].iova_base == info->iova.iov_base &&
            p->dma_bounces[idx].size == info->iova.iov_len) {
            munmap(p->dma_bounces[idx].bounce, p->dma_bounces[idx].size);
            close(p->dma_bounces[idx].fd);
            p->dma_bounces[idx].active = false;
            vfu_log(vfu_ctx, LOG_DEBUG,
                    "DMA bounce freed iova=%#lx",
                    (unsigned long)(uintptr_t)info->iova.iov_base);
            break;
        }
    }
}

static void setup_regions(struct proxy_data *p, uint32_t i)
{
    vfu_ctx_t *vfu_ctx = p->vfu_ctx;
    struct vfio_region_info ri = {
	.argsz = sizeof(ri),
	.index = i,
    };

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_REGION_INFO, &ri) == 0) {
        p->regions[i].size = ri.size;
        p->regions[i].offset = ri.offset;
        p->regions[i].flags = ri.flags;
        if (ri.size > 0) {
            vfu_log(vfu_ctx, LOG_DEBUG,
                   "region %u: size=%#lx offset=%#lx flags=%#x",
                   i, (unsigned long)ri.size, (unsigned long)ri.offset,
                   ri.flags);
            }
    } else {
        vfu_log(vfu_ctx, LOG_WARNING, "region %u: get info failed: %m", i);
    }
}

static int
setup_vfio(struct proxy_data *p, int group_num, const char *bdf)
{
    struct vfio_group_status gs = { .argsz = sizeof(gs) };
    struct vfio_device_info di = { .argsz = sizeof(di) };
    vfu_ctx_t *vfu_ctx = p->vfu_ctx;
    char path[64];
    uint32_t i;

    vfu_log(vfu_ctx, LOG_DEBUG, "opening VFIO container /dev/vfio/vfio");

    p->container_fd = open("/dev/vfio/vfio", O_RDWR);
    if (p->container_fd < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "/dev/vfio/vfio: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "container fd=%d", p->container_fd);

    if (ioctl(p->container_fd, VFIO_GET_API_VERSION) != VFIO_API_VERSION) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO API version mismatch");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "VFIO API version OK");

    snprintf(path, sizeof(path), "/dev/vfio/%d", group_num);
    p->group_fd = open(path, O_RDWR);
    if (p->group_fd < 0) {
        vfu_log(vfu_ctx, LOG_DEBUG, "%s not found, trying noiommu-%d",
                path, group_num);
        snprintf(path, sizeof(path), "/dev/vfio/noiommu-%d", group_num);
        p->group_fd = open(path, O_RDWR);
        if (p->group_fd < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "VFIO group %d: %m", group_num);
            return -1;
        }
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "opened group %s fd=%d", path, p->group_fd);

    if (ioctl(p->group_fd, VFIO_GROUP_GET_STATUS, &gs) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_GROUP_GET_STATUS: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "group status flags=%#x", gs.flags);

    if (!(gs.flags & VFIO_GROUP_FLAGS_VIABLE)) {
        vfu_log(vfu_ctx, LOG_ERR,
                "VFIO group not viable (all devices bound to vfio-pci?)");
        return -1;
    }

    if (ioctl(p->group_fd, VFIO_GROUP_SET_CONTAINER, &p->container_fd) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_GROUP_SET_CONTAINER: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "group attached to container");

    if (ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1v2_IOMMU) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "IOMMU set to TYPE1v2");
    } else if (ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_TYPE1_IOMMU) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "IOMMU set to TYPE1");
    } else if (ioctl(p->container_fd, VFIO_SET_IOMMU, VFIO_NOIOMMU_IOMMU) == 0) {
        vfu_log(vfu_ctx, LOG_INFO, "IOMMU set to NOIOMMU");
    } else {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_SET_IOMMU: %m");
        return -1;
    }

    p->device_fd = ioctl(p->group_fd, VFIO_GROUP_GET_DEVICE_FD, bdf);
    if (p->device_fd < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_GROUP_GET_DEVICE_FD(%s): %m", bdf);
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "device %s fd=%d", bdf, p->device_fd);

    if (ioctl(p->device_fd, VFIO_DEVICE_GET_INFO, &di) < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "VFIO_DEVICE_GET_INFO: %m");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_DEBUG,
            "device info: flags=%#x num_regions=%u num_irqs=%u",
            di.flags, di.num_regions, di.num_irqs);

    if (!(di.flags & VFIO_DEVICE_FLAGS_PCI)) {
        vfu_log(vfu_ctx, LOG_ERR, "%s is not a PCI device", bdf);
        return -1;
    }

    p->supports_reset = !!(di.flags & VFIO_DEVICE_FLAGS_RESET);
    vfu_log(vfu_ctx, LOG_DEBUG, "device supports reset: %s",
            p->supports_reset ? "yes" : "no");

    for (i = 0; i < di.num_regions && i < VFIO_PCI_NUM_REGIONS; i++) {
        setup_regions(p, i);
    }

    return 0;
}

static int
arm_irq_type(vfu_ctx_t *vfu_ctx, int type)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint32_t count = p->irqs[type].count;
    size_t set_sz;
    struct vfio_irq_set *irq_set;
    int *fds;
    uint32_t i;

    if (count == 0) {
        return 0;
    }

    if (p->irqs[type].efds == NULL) {
        p->irqs[type].efds = calloc(count, sizeof(int));
        if (p->irqs[type].efds == NULL) {
            return -1;
        }

        for (i = 0; i < count; i++) {
            p->irqs[type].efds[i] = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
            if (p->irqs[type].efds[i] < 0) {
                vfu_log(vfu_ctx, LOG_ERR,
                        "eventfd creation failed for IRQ type %d vec %u: %m",
                        type, i);
                goto err;
            }
        }
    }

    set_sz = sizeof(*irq_set) + count * sizeof(int);
    irq_set = calloc(1, set_sz);
    if (irq_set == NULL) {
        goto err;
    }

    irq_set->argsz = set_sz;
    irq_set->flags = VFIO_IRQ_SET_DATA_EVENTFD | VFIO_IRQ_SET_ACTION_TRIGGER;
    irq_set->index = type;
    irq_set->start = 0;
    irq_set->count = count;

    fds = (int *)(irq_set + 1);
    for (i = 0; i < count; i++) {
        fds[i] = p->irqs[type].efds[i];
    }

    if (ioctl(p->device_fd, VFIO_DEVICE_SET_IRQS, irq_set) < 0) {
        vfu_log(vfu_ctx, LOG_ERR,
                "VFIO_DEVICE_SET_IRQS type %d failed: %m", type);
        free(irq_set);
        goto err;
    }

    free(irq_set);
    vfu_log(vfu_ctx, LOG_INFO, "IRQ type %d armed (%u vectors, efds[0]=%d)",
            type, count, p->irqs[type].efds[0]);
    return 0;

err:
    for (i = 0; i < count; i++) {
        if (p->irqs[type].efds[i] >= 0) {
            close(p->irqs[type].efds[i]);
        }
    }
    free(p->irqs[type].efds);
    p->irqs[type].efds = NULL;
    return -1;
}

static const char *irq_type_name[] = {
    [VFU_DEV_INTX_IRQ] = "INTx",
    [VFU_DEV_MSI_IRQ]  = "MSI",
    [VFU_DEV_MSIX_IRQ] = "MSI-X",
    [VFU_DEV_ERR_IRQ]  = "ERR",
    [VFU_DEV_REQ_IRQ]  = "REQ",
};

#define DEFINE_IRQ_STATE_CB(vfu_type, vfio_index) \
static void \
vfu_type##_state_cb(vfu_ctx_t *vfu_ctx, uint32_t start, \
                    uint32_t count, bool mask) \
{ \
    struct proxy_data *p = vfu_get_private(vfu_ctx); \
    struct vfio_irq_set irq_set = { \
        .argsz = sizeof(irq_set), \
        .flags = VFIO_IRQ_SET_DATA_NONE | \
                 (mask ? VFIO_IRQ_SET_ACTION_MASK \
                       : VFIO_IRQ_SET_ACTION_UNMASK), \
        .index = vfio_index, \
        .start = start, \
        .count = count, \
    }; \
\
    vfu_log(vfu_ctx, LOG_INFO, "%s %s vec [%u, %u)", \
            irq_type_name[vfu_type], mask ? "mask" : "unmask", \
            start, start + count); \
\
    if (ioctl(p->device_fd, VFIO_DEVICE_SET_IRQS, &irq_set) < 0) { \
        vfu_log(vfu_ctx, LOG_ERR, "%s %s vec [%u, %u) failed: %m", \
                irq_type_name[vfu_type], mask ? "mask" : "unmask", \
                start, start + count); \
    } \
}

DEFINE_IRQ_STATE_CB(VFU_DEV_INTX_IRQ, VFIO_PCI_INTX_IRQ_INDEX)
DEFINE_IRQ_STATE_CB(VFU_DEV_MSI_IRQ, VFIO_PCI_MSI_IRQ_INDEX)
DEFINE_IRQ_STATE_CB(VFU_DEV_MSIX_IRQ, VFIO_PCI_MSIX_IRQ_INDEX)
DEFINE_IRQ_STATE_CB(VFU_DEV_ERR_IRQ, VFIO_PCI_ERR_IRQ_INDEX)
DEFINE_IRQ_STATE_CB(VFU_DEV_REQ_IRQ, VFIO_PCI_REQ_IRQ_INDEX)

static vfu_dev_irq_state_cb_t *irq_state_cbs[] = {
    [VFU_DEV_INTX_IRQ] = VFU_DEV_INTX_IRQ_state_cb,
    [VFU_DEV_MSI_IRQ]  = VFU_DEV_MSI_IRQ_state_cb,
    [VFU_DEV_MSIX_IRQ] = VFU_DEV_MSIX_IRQ_state_cb,
    [VFU_DEV_ERR_IRQ]  = VFU_DEV_ERR_IRQ_state_cb,
    [VFU_DEV_REQ_IRQ]  = VFU_DEV_REQ_IRQ_state_cb,
};

static int
setup_irqs(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    struct vfio_irq_info irq;
    int i, ret;

    for (i = 0; i < VFU_DEV_NUM_IRQS; i++) {
        memset(&irq, 0, sizeof(irq));
        irq.argsz = sizeof(irq);
        irq.index = i;

        if (ioctl(p->device_fd, VFIO_DEVICE_GET_IRQ_INFO, &irq) < 0 ||
            irq.count == 0) {
            continue;
        }

        p->irqs[i].count = irq.count;

        vfu_log(vfu_ctx, LOG_DEBUG, "IRQ type %d: count=%u flags=%#x",
                i, irq.count, irq.flags);

        ret = vfu_setup_device_nr_irqs(vfu_ctx, i, irq.count);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "vfu_setup_device_nr_irqs(%d): %m", i);
            return -1;
        }
    }

    /*
     * Only arm INTx, ERR, and REQ at startup.  MSI/MSI-X must wait until
     * the guest enables them (detected in cfg_access), because the kernel
     * VFIO driver only supports one of INTx/MSI/MSI-X active at a time —
     * arming MSI-X here would disable INTx before the guest is ready.
     */
    for (i = 0; i < VFU_DEV_NUM_IRQS; i++) {
        if (p->irqs[i].count == 0) {
            continue;
        }

        if (i == VFU_DEV_INTX_IRQ || i == VFU_DEV_ERR_IRQ ||
            i == VFU_DEV_REQ_IRQ) {
            ret = arm_irq_type(vfu_ctx, i);
            if (ret < 0) {
                vfu_log(vfu_ctx, LOG_INFO,
                        "%s: arming failed, forwarding not available",
                        irq_type_name[i]);
            } else {
                vfu_log(vfu_ctx, LOG_INFO,
                        "%s: armed %u vectors",
                        irq_type_name[i], p->irqs[i].count);
            }
        }

        ret = vfu_setup_irq_state_callback(vfu_ctx, i, irq_state_cbs[i]);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "%s: vfu_setup_irq_state_callback failed: %m",
                    irq_type_name[i]);
        }
    }

    return 0;
}

static int
pci_flags_to_vfu_flags(uint32_t bar_val)
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
    uint64_t cfg_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
    int ret, flags, i;
    uint32_t bar_val;

    for (i = 0; i < PCI_BARS_NR; i++) {
        if (p->regions[i].size == 0) {
            vfu_log(vfu_ctx, LOG_DEBUG, "BAR%d is zero size.", i);
            continue;
        }

        if (pread(p->device_fd, &bar_val, 4,
                  cfg_off + PCI_BASE_ADDRESS_0 + i * 4) != 4) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to read BAR%d config: %m", i);
            continue;
        }

        flags = pci_flags_to_vfu_flags(bar_val);

        ret = setup_region_memfd(vfu_ctx, VFU_PCI_DEV_BAR0_REGION_IDX + i,
                                 p->regions[i].size, bar_cbs[i], flags);

        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR, "failed to setup BAR%d: %m", i);
            continue;
        }

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
    uint64_t cfg_off = p->regions[VFIO_PCI_CONFIG_REGION_INDEX].offset;
    uint16_t vendor_id, device_id, subsys_vid, subsys_id;
    uint8_t class_info[3];
    uint8_t ipin;

    vfu_log(vfu_ctx, LOG_INFO,
            "config region: offset=%#lx size=%#lx fd=%d",
            (unsigned long)cfg_off,
            (unsigned long)p->regions[VFIO_PCI_CONFIG_REGION_INDEX].size,
            p->device_fd);

    if (pread(p->device_fd, &vendor_id, 2, cfg_off + PCI_VENDOR_ID) != 2 ||
        pread(p->device_fd, &device_id, 2, cfg_off + PCI_DEVICE_ID) != 2 ||
        pread(p->device_fd, &subsys_vid, 2, cfg_off + PCI_SUBSYSTEM_VENDOR_ID) != 2 ||
        pread(p->device_fd, &subsys_id, 2, cfg_off + PCI_SUBSYSTEM_ID) != 2 ||
        pread(p->device_fd, class_info, 3, cfg_off + PCI_CLASS_PROG) != 3 ||
        pread(p->device_fd, &ipin, 1, cfg_off + PCI_INTERRUPT_PIN) != 1) {
        vfu_log(vfu_ctx, LOG_ERR, "failed to read PCI config identity fields");
        return -1;
    }

    vfu_log(vfu_ctx, LOG_INFO, "PCI ID [%04x:%04x] subsys [%04x:%04x] "
            "class %02x%02x%02x ipin=%u",
            vendor_id, device_id, subsys_vid, subsys_id,
            class_info[2], class_info[1], class_info[0], ipin);

    vfu_pci_set_id(vfu_ctx, vendor_id, device_id, subsys_vid, subsys_id);
    vfu_pci_set_class(vfu_ctx, class_info[2], class_info[1], class_info[0]);
    vfu_pci_get_config_space(vfu_ctx)->hdr.intr.ipin = ipin;

    /* Walk capabilities to find MSI and MSI-X offsets. */
    uint16_t status;
    uint8_t cap_ptr, cap_id;

    if (pread(p->device_fd, &status, 2, cfg_off + PCI_STATUS) == 2 &&
        (status & PCI_STATUS_CAP_LIST)) {
        if (pread(p->device_fd, &cap_ptr, 1,
                  cfg_off + PCI_CAPABILITY_LIST) == 1) {
            cap_ptr &= ~3;
            while (cap_ptr >= 0x40) {
                if (pread(p->device_fd, &cap_id, 1,
                          cfg_off + cap_ptr) != 1) {
                    break;
                }
                vfu_log(vfu_ctx, LOG_DEBUG,
                        "PCI cap 0x%02x at offset 0x%02x", cap_id, cap_ptr);
                if (cap_id == PCI_CAP_ID_MSIX) {
                    p->msix_cap_off = cap_ptr;
                    vfu_log(vfu_ctx, LOG_INFO,
                            "MSI-X capability at 0x%02x", cap_ptr);
                } else if (cap_id == PCI_CAP_ID_MSI) {
                    p->msi_cap_off = cap_ptr;
                    vfu_log(vfu_ctx, LOG_INFO,
                            "MSI capability at 0x%02x", cap_ptr);
                }
                if (pread(p->device_fd, &cap_ptr, 1,
                          cfg_off + cap_ptr + 1) != 1) {
                    break;
                }
                cap_ptr &= ~3;
            }
        }
    }

    return 0;
}

static int
build_poll_fds(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    int total = POLL_IRQ_START;
    int idx, i;
    uint32_t j;

    for (i = 0; i < VFU_DEV_NUM_IRQS; i++) {
        if (p->irqs[i].efds != NULL) {
            total += p->irqs[i].count;
        }
    }

    free(p->fds);
    free(p->irq_map);

    p->fds = calloc(total, sizeof(struct pollfd));
    p->irq_map = calloc(total, sizeof(struct poll_irq_entry));
    if (p->fds == NULL || p->irq_map == NULL) {
        free(p->fds);
        free(p->irq_map);
        p->fds = NULL;
        p->irq_map = NULL;
        return -1;
    }

    p->fds[POLL_VFU].fd = vfu_get_poll_fd(vfu_ctx);
    p->fds[POLL_VFU].events = POLLIN;

    idx = POLL_IRQ_START;
    for (i = 0; i < VFU_DEV_NUM_IRQS; i++) {
        if (p->irqs[i].efds == NULL) {
            continue;
        }
        for (j = 0; j < p->irqs[i].count; j++) {
            p->fds[idx].fd = p->irqs[i].efds[j];
            p->fds[idx].events = POLLIN;
            p->irq_map[idx].type = i;
            p->irq_map[idx].vec = j;
            idx++;
        }
    }

    p->nfds = total;

    vfu_log(vfu_ctx, LOG_INFO, "poll fds: %d total (%d IRQ vectors)",
            total, total - POLL_IRQ_START);

    return 0;
}

static int
setup_device(vfu_ctx_t *vfu_ctx, bool no_rom)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    int ret;

    if (!no_rom && p->regions[VFIO_PCI_ROM_REGION_INDEX].size > 0) {
        ret = setup_region_memfd(vfu_ctx, VFU_PCI_DEV_ROM_REGION_IDX,
                                 p->regions[VFIO_PCI_ROM_REGION_INDEX].size,
                                 &rom_access, VFU_REGION_FLAG_READ);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_WARNING, "ROM region setup failed: %m");
        }
    }
    ret = setup_region_memfd(vfu_ctx, VFU_PCI_DEV_CFG_REGION_IDX,
                             PCI_CFG_SPACE_SIZE, &cfg_access,
                             VFU_REGION_FLAG_RW | VFU_REGION_FLAG_ALWAYS_CB);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "config region setup: %m");
        return -1;
    }

    ret = vfu_setup_device_reset_cb(vfu_ctx, &device_reset);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_setup_device_reset_cb: %m");
        return -1;
    }

    ret = vfu_setup_device_dma(vfu_ctx, LIBVFIO_USER_MAX_DMA_REGIONS,
                               dma_register, dma_unregister);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "vfu_setup_device_dma: %m");
        return -1;
    }

    ret = setup_irqs(vfu_ctx);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "IRQ setup failed");
        return -1;
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

    ret = build_poll_fds(vfu_ctx);
    if (ret < 0) {
        vfu_log(vfu_ctx, LOG_ERR, "build_poll_fds: %m");
        return -1;
    }

    return 0;
}

static void
sync_dma_to_guest(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    dma_sg_t *sg = alloca(dma_sg_size());

    for (int i = 0; i < MAX_DMA_BOUNCES; i++) {
        struct dma_bounce *db = &p->dma_bounces[i];
        int ret;

        if (!db->active) {
            continue;
        }

        ret = vfu_addr_to_sgl(vfu_ctx, (vfu_dma_addr_t)db->iova_base,
                              db->size, sg, 1, PROT_WRITE);
        if (ret < 0) {
            continue;
        }

        ret = vfu_sgl_write(vfu_ctx, sg, 1, db->bounce, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "DMA bounce→guest write failed iova=%#lx size=%#lx: %m",
                    (unsigned long)(uintptr_t)db->iova_base,
                    (unsigned long)db->size);
        }
    }
}

static void
sync_dma_from_guest(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    dma_sg_t *sg = alloca(dma_sg_size());

    for (int i = 0; i < MAX_DMA_BOUNCES; i++) {
        struct dma_bounce *db = &p->dma_bounces[i];
        int ret;

        if (!db->active) {
            continue;
        }

        ret = vfu_addr_to_sgl(vfu_ctx, (vfu_dma_addr_t)db->iova_base,
                              db->size, sg, 1, PROT_READ);
        if (ret < 0) {
            continue;
        }

        ret = vfu_sgl_read(vfu_ctx, sg, 1, db->bounce, 0);
        if (ret < 0) {
            vfu_log(vfu_ctx, LOG_ERR,
                    "DMA guest bounce read failed iova=%#lx size=%#lx: %m",
                    (unsigned long)(uintptr_t)db->iova_base,
                    (unsigned long)db->size);
        }
    }
}

static int
proxy_run(vfu_ctx_t *vfu_ctx)
{
    struct proxy_data *p = vfu_get_private(vfu_ctx);
    uint64_t val;
    ssize_t cnt;
    int ret, i;

    for (;;) {
        sync_dma_from_guest(vfu_ctx);
        sync_dma_to_guest(vfu_ctx);

        ret = poll(p->fds, p->nfds, -1);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            vfu_log(vfu_ctx, LOG_ERR, "poll: %m");
            return -1;
        }

        for (i = POLL_IRQ_START; i < p->nfds; i++) {
            if (!(p->fds[i].revents & POLLIN)) {
                continue;
            }
            cnt = read(p->fds[i].fd, &val, sizeof(val));
            if (cnt == (ssize_t)sizeof(val)) {
                int type = p->irq_map[i].type;
                int vec = p->irq_map[i].vec;

                vfu_log(vfu_ctx, LOG_DEBUG,
                        "IRQ fired type=%d vec=%d count=%lu",
                        type, vec, (unsigned long)val);

                if (vfu_irq_trigger(vfu_ctx, vec) < 0) {
                    vfu_log(vfu_ctx, LOG_ERR,
                            "vfu_irq_trigger(vec=%d) failed: %m", vec);
                }
            }
            if (cnt < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                vfu_log(vfu_ctx, LOG_ERR,
                        "read IRQ eventfd idx=%d: %m", i);
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

static int
get_iommu_group(const char *bdf)
{
    char target[PATH_MAX];
    char path[PATH_MAX];
    ssize_t len;

    snprintf(path, sizeof(path),
             "/sys/bus/pci/devices/%s/iommu_group", bdf);
    len = readlink(path, target, sizeof(target) - 1);
    if (len < 0 || len >= (ssize_t)(sizeof(target) - 1)) {
        err(EXIT_FAILURE, "readlink %s", path);
    }

    target[len] = '\0';
    return atoi(basename(target));
}

struct proxy_opts {
    const char *sock_path;
    const char *bdf;
    int log_level;
    bool no_rom;
};

static void __attribute__((noreturn))
usage(const char *prog)
{
    fprintf(stderr,
            "Usage: %s [-vv] [-R] <socketpath> <device-bdf>\n"
            "  -R  disable ROM BAR\n",
            prog);
    exit(EXIT_FAILURE);
}

static struct proxy_opts
parse_args(int argc, char *argv[])
{
    struct proxy_opts opts = {
        .log_level = LOG_ERR,
    };
    int opt;

    while ((opt = getopt(argc, argv, "vR")) != -1) {
        switch (opt) {
        case 'v':
            if (opts.log_level < LOG_DEBUG) {
                opts.log_level++;
            }
            break;
        case 'R':
            opts.no_rom = true;
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
    struct proxy_data proxy = {
        .container_fd = -1,
        .group_fd = -1,
        .device_fd = -1,
        .log_level = LOG_ERR,
    };
    struct proxy_opts opts;
    vfu_ctx_t *vfu_ctx;

    for (int i = 0; i < VFIO_PCI_NUM_REGIONS; i++) {
        proxy.reg_memfd[i] = -1;
    }
    int group_num, ret;

    opts = parse_args(argc, argv);
    group_num = get_iommu_group(opts.bdf);
    proxy.log_level = opts.log_level;

    vfu_ctx = vfu_create_ctx(VFU_TRANS_SOCK, opts.sock_path, 0, &proxy,
                             VFU_DEV_TYPE_PCI);
    if (vfu_ctx == NULL) {
        err(EXIT_FAILURE, "vfu_create_ctx");
    }

    proxy.vfu_ctx = vfu_ctx;

    ret = vfu_setup_log(vfu_ctx, proxy_log, proxy.log_level);
    if (ret < 0) {
        warn("vfu_setup_log");
        goto cleanup;
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "creating vfu context on %s", opts.sock_path);

    ret = setup_vfio(&proxy, group_num, opts.bdf);
    if (ret < 0) {
        goto cleanup;
    }

    if (proxy.regions[VFIO_PCI_CONFIG_REGION_INDEX].size == 0) {
        vfu_log(vfu_ctx, LOG_ERR, "%s: no config region", opts.bdf);
        ret = -1;
        goto cleanup;
    }

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

    ret = setup_device(vfu_ctx, opts.no_rom);
    if (ret < 0) {
        goto cleanup;
    }

    vfu_log(vfu_ctx, LOG_INFO, "serving %s on %s", opts.bdf, opts.sock_path);

    ret = proxy_run(vfu_ctx);
    vfu_log(vfu_ctx, LOG_DEBUG, "main loop exited (ret=%d)", ret);

cleanup:
    for (int i = 0; i < VFU_DEV_NUM_IRQS; i++) {
        for (uint32_t j = 0; j < proxy.irqs[i].count; j++) {
            if (proxy.irqs[i].efds && proxy.irqs[i].efds[j] >= 0) {
                close(proxy.irqs[i].efds[j]);
            }
        }
        free(proxy.irqs[i].efds);
    }
    free(proxy.fds);
    free(proxy.irq_map);

    for (int i = 0; i < MAX_DMA_BOUNCES; i++) {
        if (proxy.dma_bounces[i].active) {
            munmap(proxy.dma_bounces[i].bounce, proxy.dma_bounces[i].size);
            close(proxy.dma_bounces[i].fd);
        }
    }
    for (int i = 0; i < VFIO_PCI_NUM_REGIONS; i++) {
        if (proxy.reg_mmap[i] != NULL) {
            munmap(proxy.reg_mmap[i], proxy.regions[i].size);
        }
        if (proxy.reg_memfd[i] >= 0) {
            close(proxy.reg_memfd[i]);
        }
    }

    vfu_log(vfu_ctx, LOG_DEBUG, "cleaning up vfu context");
    vfu_destroy_ctx(vfu_ctx);

    close_safely(&proxy.device_fd);
    close_safely(&proxy.group_fd);
    close_safely(&proxy.container_fd);

    return ret == 0 ? EXIT_SUCCESS : EXIT_FAILURE;
}

/* ex: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab: */
