#!/bin/bash
#
# Runs inside the L1 VM. Builds libvfio-user, binds an emulated e1000 to
# vfio-pci, starts vfio-user-proxy, and starts sshd so the host can
# forward the proxy socket.
#
set -e

LIBVFIO_SRC="/run/live/persistence/vda/libvfio-user"

install_packages() {
    echo "--- Installing packages ---"
    apt-get update
    apt-get install -y \
        build-essential meson ninja-build libjson-c-dev libcmocka-dev \
        pkg-config pciutils kmod openssh-server
    apt-get clean
}

setup_ssh() {
    echo "--- Setting up SSH ---"
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    systemctl enable --now ssh
}

build_libvfio() {
    echo "--- Building libvfio-user ---"
    cd "$LIBVFIO_SRC"
    meson setup build
    ninja -C build samples/vfio-user-proxy
    echo "Build OK"
}

setup_vfio() {
    local bdf="$1"

    echo "--- Setting up VFIO ---"
    modprobe vfio
    modprobe vfio-pci
    modprobe vfio_iommu_type1
    echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts

    echo vfio-pci > /sys/bus/pci/devices/"$bdf"/driver_override
    echo "$bdf" > /sys/bus/pci/drivers_probe
}

echo "=== vfio-user-proxy test ==="

install_packages
setup_ssh
build_libvfio

E1000_BDF=$(lspci -D -d 8086:100e | head -1 | awk '{print $1}')
if [ -z "$E1000_BDF" ]; then
    echo "ERROR: No e1000 device found"
    return 1
fi

setup_vfio "$E1000_BDF"

VFIO_GROUP=$(basename "$(readlink /sys/bus/pci/devices/"$E1000_BDF"/iommu_group)")
"$LIBVFIO_SRC"/build/samples/vfio-user-proxy -v \
        /tmp/proxy.sock "$VFIO_GROUP" "$E1000_BDF"
