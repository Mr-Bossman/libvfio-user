#!/bin/bash
#
# Runs inside the L1 VM. Builds libvfio-user, binds an emulated e1000 to
# vfio-pci, starts vfio-user-proxy, then launches a nested VM (L2) that
# accesses the proxied device via QEMU's vfio-user-pci.
#
set -e

echo "=== vfio-user-proxy nested VM test ==="

echo "--- Installing packages ---"
apt-get update
apt-get install -y \
    build-essential meson ninja-build libjson-c-dev libcmocka-dev \
    pkg-config pciutils kmod qemu-system-x86
apt-get clean

echo "--- Building libvfio-user ---"
cd /run/live/persistence/vda/libvfio-user
meson setup build
ninja -C build samples/vfio-user-proxy
echo "Build OK"

echo "--- PCI devices ---"
lspci

E1000_BDF=$(lspci -D -d 8086:100e | head -1 | awk '{print $1}')
if [ -z "$E1000_BDF" ]; then
    echo "ERROR: No e1000 device found"
    exit 1
fi
echo "Target device: $E1000_BDF"

echo "--- Setting up VFIO ---"
modprobe vfio
modprobe vfio-pci
modprobe vfio_iommu_type1
echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts

echo vfio-pci > /sys/bus/pci/devices/"$E1000_BDF"/driver_override
echo "$E1000_BDF" > /sys/bus/pci/drivers_probe

VFIO_GROUP=$(basename "$(readlink /sys/bus/pci/devices/"$E1000_BDF"/iommu_group)")
echo "VFIO group: $VFIO_GROUP"
ls -l /dev/vfio/

echo "--- Starting vfio-user-proxy ---"
/run/live/persistence/vda/libvfio-user/build/samples/vfio-user-proxy -v \
    /tmp/proxy.sock "$VFIO_GROUP" "$E1000_BDF" &
PROXY_PID=$!
sleep 1

if ! kill -0 "$PROXY_PID" 2>/dev/null; then
    echo "ERROR: proxy failed to start"
    exit 1
fi
echo "Proxy running (PID $PROXY_PID)"

exit
echo "--- Starting nested VM (L2) ---"
qemu-system-x86_64 \
    -m 2G -enable-kvm -cpu host \
    -kernel /vmlinuz \
    -initrd /initrd.img \
    -cdrom /dev/cdrom \
    -append "boot=live console=ttyS0" \
    -device '{"driver":"vfio-user-pci","socket":{"type":"unix","path":"/tmp/proxy.sock"}}' \
    -echr 0x02 -nographic \
    || echo "L2 VM exited with code $?"

kill "$PROXY_PID" 2>/dev/null
wait "$PROXY_PID" 2>/dev/null

echo "=== Test complete ==="
