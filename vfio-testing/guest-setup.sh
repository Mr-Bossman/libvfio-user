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
        pkg-config pciutils kmod openssh-server git libnvme-dev
    apt-get clean
}

setup_ssh() {
    echo "--- Setting up SSH ---"
    sed -i 's/^#*PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
    systemctl enable --now ssh
}

build_libvfn() {
    echo "--- Building and installing libvfn ---"
    git clone https://github.com/SamsungDS/libvfn.git /tmp/libvfn
    cd /tmp/libvfn
    meson setup build -Ddocs=disabled
    ninja -C build
    meson install -C build
    ldconfig
    echo "libvfn installed"
}

build_libvfio() {
    echo "--- Building libvfio-user ---"
    cd "$LIBVFIO_SRC"
    meson setup build --reconfigure || meson setup build
    ninja -C build samples/vfio-user-proxy
    echo "Build OK"
}

install_proxy_service() {
    local bdf="$1"

    cat > /usr/local/bin/start-pci-proxy.sh << 'EOF'
#!/bin/bash
set -e
BDF="$1"
if [ -z "$BDF" ] || [ ! -d "/sys/bus/pci/devices/$BDF" ]; then
    echo "ERROR: invalid BDF: $BDF" >&2
    exit 1
fi
modprobe vfio
modprobe vfio-pci
modprobe vfio_iommu_type1
echo 1 > /sys/module/vfio_iommu_type1/parameters/allow_unsafe_interrupts
echo vfio-pci > /sys/bus/pci/devices/$BDF/driver_override
echo $BDF > /sys/bus/pci/drivers_probe
exec /run/live/persistence/vda/libvfio-user/build/samples/vfio-user-proxy -v /run/vfio-user-proxy/proxy.sock $BDF
EOF
    chmod +x /usr/local/bin/start-pci-proxy.sh

    cat > /etc/systemd/system/vfio-user-proxy.service << EOF
[Unit]
Description=vfio-user-proxy
After=network.target

[Service]
Type=simple
RuntimeDirectory=vfio-user-proxy
ExecStart=/usr/local/bin/start-pci-proxy.sh $bdf
Restart=always
RestartSec=1
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable --now vfio-user-proxy
}

echo "=== vfio-user-proxy test ==="

install_packages
setup_ssh
build_libvfn
build_libvfio

E1000_BDF=$(lspci -D -d 8086:100e | head -1 | awk '{print $1}')
if [ -z "$E1000_BDF" ]; then
    echo "ERROR: No e1000 device found"
    exit 1
fi

install_proxy_service "$E1000_BDF"

systemctl disable guest-setup.service

echo "=== PROXY READY ==="
