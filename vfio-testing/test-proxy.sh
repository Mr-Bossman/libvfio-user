#!/bin/bash
#
# Starts an L1 VM (Debian live) with an emulated e1000 NIC and nested KVM.
# Inside L1, guest-setup.sh builds libvfio-user, binds the e1000 to vfio-pci,
# runs vfio-user-proxy, and launches a nested L2 VM that accesses the device
# via QEMU's vfio-user-pci.
#
# Usage: sudo ./test-proxy.sh
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
LIBVFIO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

ISO="$SCRIPT_DIR/debian-live-testing-amd64-standard.iso"

if [ ! -f "$ISO" ]; then
    echo "Missing $(basename "$ISO") in $SCRIPT_DIR"
    exit 1
fi

if [ ! -d "$LIBVFIO_DIR" ]; then
    echo "libvfio-user source not found at $LIBVFIO_DIR"
    exit 1
fi

TMPDIR=$(mktemp -d)
cleanup() {
    umount "$TMPDIR/iso" "$TMPDIR/persist-mnt" 2>/dev/null || true
    rm -rf "$TMPDIR"
}
trap cleanup EXIT INT TERM

echo "=== Extracting kernel and initrd from ISO ==="
MNTDIR="$TMPDIR/iso"
mkdir -p "$MNTDIR"

mount -o loop,ro "$ISO" "$MNTDIR" 2>/dev/null ||
    fuseiso "$ISO" "$MNTDIR" 2>/dev/null ||
    { echo "Cannot mount ISO (try: sudo $0, or install fuseiso)"; exit 1; }

cp "$MNTDIR/live/vmlinuz" "$TMPDIR/vmlinuz"
cp "$MNTDIR/live/initrd.img" "$TMPDIR/initrd.img"

umount "$MNTDIR" 2>/dev/null || fusermount -u "$MNTDIR" 2>/dev/null || true

echo "=== Building persistence image ==="
PERSIST_IMG="$TMPDIR/persistence.img"
truncate -s 1G "$PERSIST_IMG"
mkfs.ext4 -q -L persistence "$PERSIST_IMG"

PERSIST_MNT="$TMPDIR/persist-mnt"
mkdir -p "$PERSIST_MNT"
mount -o loop "$PERSIST_IMG" "$PERSIST_MNT"

echo "/ union" > "$PERSIST_MNT/persistence.conf"

# live-boot overlayfs: upper layer in rw/
RW="$PERSIST_MNT/rw"
mkdir -p "$RW"

# Autologin on serial console
mkdir -p "$RW/etc/systemd/system/serial-getty@ttyS0.service.d"
cat > "$RW/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
EOF

# guest-setup script
mkdir -p "$RW/usr/local/bin"
cp "$SCRIPT_DIR/guest-setup.sh" "$RW/usr/local/bin/guest-setup.sh"
chmod +x "$RW/usr/local/bin/guest-setup.sh"

# libvfio-user source (outside overlay, accessed by guest-setup.sh directly)
rsync -a --exclude='.git' --exclude='build' "$LIBVFIO_DIR/" "$PERSIST_MNT/libvfio-user/"

umount "$PERSIST_MNT"

echo "=== Starting L1 VM ==="
echo ""
echo "  e1000 NIC   -> passthrough target (no backend)"
echo "  virtio-net  -> network for apt"
echo "  persistence -> autologin + guest-setup + libvfio-user source"
echo ""

qemu-system-x86_64 \
    -machine q35 \
    -smp 4 -m 4G \
    -enable-kvm -cpu host \
    -kernel "$TMPDIR/vmlinuz" \
    -initrd "$TMPDIR/initrd.img" \
    -cdrom "$ISO" \
    -drive file="$PERSIST_IMG",format=raw,if=virtio \
    -append "boot=live console=ttyS0 modprobe.blacklist=e1000 persistence intel_iommu=on" \
    -device intel-iommu \
    -device e1000 \
    -nic user,model=virtio-net-pci \
    -nographic
