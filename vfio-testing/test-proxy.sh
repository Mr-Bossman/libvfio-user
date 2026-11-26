#!/bin/bash
#
# Starts an L1 VM (Debian live) with an emulated e1000 NIC and nested KVM.
# Inside L1, guest-setup.sh builds libvfio-user, binds the e1000 to vfio-pci,
# and runs vfio-user-proxy. L2 runs inside L1 using nested virtualization,
# accessing the proxy socket directly via QEMU's vfio-user-pci.
#
# The persistence image is cached in $SCRIPT_DIR/.cache/
# so subsequent runs skip image creation and package installation.
#
# Usage: sudo ./test-proxy.sh [/path/to/libvfio-user]
#
set -e

SCRIPT_DIR="$(realpath "$(dirname "$0")")"
LIBVFIO_DIR="$(realpath "${1:-$SCRIPT_DIR/..}")"
CACHE_DIR="$SCRIPT_DIR/.cache"
ISO="$SCRIPT_DIR/debian-live-testing-amd64-standard.iso"
PERSIST_IMG="$CACHE_DIR/persistence.img"
SSH_KEY="$CACHE_DIR/test-key"
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -i $SSH_KEY"
TMUX_SESSION="vfio-test"

check_prereqs() {
    local cmd
    for cmd in tmux qemu-system-x86_64 ssh rsync mkfs.ext4 curl; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            echo "Missing required command: $cmd"
            exit 1
        fi
    done

    if [ ! -f "$ISO" ]; then
        echo "=== Downloading $(basename "$ISO") ==="
        curl -L -o "$ISO" \
            "https://cdimage.debian.org/cdimage/weekly-live-builds/amd64/iso-hybrid/debian-live-testing-amd64-standard.iso"
    fi

    if [ ! -d "$LIBVFIO_DIR" ]; then
        echo "libvfio-user source not found at $LIBVFIO_DIR"
        exit 1
    fi
}

extract_kernel() {
    local tmpdir="$1"
    local mntdir="$tmpdir/iso"

    echo "=== Extracting kernel and initrd from ISO ==="
    mkdir -p "$mntdir"

    mount -o loop,ro "$ISO" "$mntdir" 2>/dev/null ||
        fuseiso "$ISO" "$mntdir" 2>/dev/null ||
        { echo "Cannot mount ISO (try: sudo $0, or install fuseiso)"; exit 1; }

    cp "$mntdir/live/vmlinuz" "$tmpdir/vmlinuz"
    cp "$mntdir/live/initrd.img" "$tmpdir/initrd.img"

    umount "$mntdir" 2>/dev/null || fusermount -u "$mntdir" 2>/dev/null || true
}

mount_persistence() {
    local tmpdir="$1"
    local persist_mnt="$tmpdir/persist-mnt"

    mkdir -p "$persist_mnt"
    mount -o loop "$PERSIST_IMG" "$persist_mnt"
    echo "$persist_mnt"
}

create_persistence() {
    local tmpdir="$1"

    if [ -f "$PERSIST_IMG" ]; then
        echo "=== Reusing cached persistence image ==="
        return
    fi

    echo "=== Creating persistence image (first run) ==="
    mkdir -p "$CACHE_DIR"

    if [ ! -f "$SSH_KEY" ]; then
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -q
    fi

    truncate -s 4G "$PERSIST_IMG"
    mkfs.ext4 -q -L persistence "$PERSIST_IMG"

    local persist_mnt
    persist_mnt=$(mount_persistence "$tmpdir")

    echo "/ union" > "$persist_mnt/persistence.conf"

    local rw="$persist_mnt/rw"
    mkdir -p "$rw"

    # Autologin on serial console
    mkdir -p "$rw/etc/systemd/system/serial-getty@ttyS0.service.d"
    cat > "$rw/etc/systemd/system/serial-getty@ttyS0.service.d/autologin.conf" << 'EOF'
[Service]
ExecStart=
ExecStart=-/sbin/agetty --autologin root --noclear %I $TERM
EOF

    # guest-setup systemd service
    cat > "$rw/etc/systemd/system/guest-setup.service" << 'EOF'
[Unit]
Description=Run guest-setup.sh
After=network-online.target local-fs.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /usr/local/bin/guest-setup.sh
StandardOutput=journal+console
StandardError=journal+console

[Install]
WantedBy=multi-user.target
EOF
    mkdir -p "$rw/etc/systemd/system/multi-user.target.wants"
    ln -sf ../guest-setup.service \
        "$rw/etc/systemd/system/multi-user.target.wants/guest-setup.service"

    # Enable root login via SSH
    mkdir -p "$rw/etc/ssh/sshd_config.d"
    cat > "$rw/etc/ssh/sshd_config.d/root.conf" << 'EOF'
PermitRootLogin yes
EOF

    mkdir -p "$rw/root/.ssh"
    chmod 700 "$rw/root/.ssh"
    cp "$SSH_KEY.pub" "$rw/root/.ssh/authorized_keys"
    chmod 600 "$rw/root/.ssh/authorized_keys"

    mkdir -p "$persist_mnt/rw/usr/local/bin"
    cp "$SCRIPT_DIR/guest-setup.sh" "$persist_mnt/rw/usr/local/bin/guest-setup.sh"

    umount "$persist_mnt"
}

update_persistence() {
    local tmpdir="$1"

    echo "=== Updating guest-setup.sh and libvfio-user source ==="
    local persist_mnt
    persist_mnt=$(mount_persistence "$tmpdir")

    cp "$SCRIPT_DIR/guest-setup.sh" "$persist_mnt/rw/usr/local/bin/guest-setup.sh"
    chmod +x "$persist_mnt/rw/usr/local/bin/guest-setup.sh"

    rsync -a --exclude='.git' --exclude='build' --exclude='vfio-testing' --delete "$LIBVFIO_DIR/" "$persist_mnt/libvfio-user/"

    umount "$persist_mnt"
    rmdir "$persist_mnt"
}

start_l1() {
    local tmpdir="$1"

    echo "=== Starting L1 VM ==="
    echo ""
    echo "  e1000       -> passthrough target (MMIO + DMA)"
    echo "  virtio-net  -> network for apt (SSH on host port 2222)"
    echo "  persistence -> autologin + guest-setup + libvfio-user source"
    echo "  attach:       tmux attach -t $TMUX_SESSION"
    echo ""

    tmux new-session -d -s "$TMUX_SESSION" -n L1 \
        "qemu-system-x86_64 \
            -machine q35 \
            -smp 4 -m 4G \
            -enable-kvm -cpu host \
            -kernel '$tmpdir/vmlinuz' \
            -initrd '$tmpdir/initrd.img' \
            -cdrom '$ISO' \
            -drive file='$PERSIST_IMG',format=raw,if=virtio \
            -append 'boot=live console=ttyS0 modprobe.blacklist=e1000 persistence intel_iommu=on' \
            -device intel-iommu \
            -netdev user,id=e1knet -device e1000,netdev=e1knet \
            -nic user,model=virtio-net-pci,hostfwd=tcp::2222-:22 \
            -nographic"
}

wait_for_ssh() {
    echo "=== Waiting for SSH in L1 ==="
    local i
    for i in $(seq 1 120); do
        if ssh $SSH_OPTS -p 2222 root@localhost true 2>/dev/null; then
            echo "SSH ready"
            return 0
        fi
        sleep 2
    done
    echo "ERROR: SSH not available in L1"
    return 1
}

open_l1_shell() {
    echo "=== Opening SSH shell to L1 — waiting for proxy, then starting L2 ==="

    tmux split-window -h -t "$TMUX_SESSION" \
        "ssh $SSH_OPTS -p 2222 -t root@localhost \
            'echo \"Waiting for proxy...\"; \
             while [ ! -S /run/vfio-user-proxy/proxy.sock ]; do sleep 1; done; \
             echo \"Proxy ready, starting L2\"; \
             /usr/local/bin/start-l2.sh'"
}

wait_for_session() {
    while tmux has-session -t $TMUX_SESSION 2>/dev/null; do
        sleep 2
    done
}

teardown() {
    tmux kill-session -t $TMUX_SESSION 2>/dev/null || true
    echo "=== Test complete ==="
}

cleanup() {
    local tmpdir="$1"
    umount "$tmpdir/iso" "$tmpdir/persist-mnt" 2>/dev/null || true
    tmux kill-session -t $TMUX_SESSION 2>/dev/null || true
    rm -rf "$tmpdir"
}

TMPDIR=$(mktemp -d)
trap 'cleanup "$TMPDIR"' EXIT INT TERM

check_prereqs
extract_kernel "$TMPDIR"
create_persistence "$TMPDIR"
update_persistence "$TMPDIR"
start_l1 "$TMPDIR"
echo "=== Attach: \`tmux attach -t $TMUX_SESSION\` ==="
echo "=== L2 will start automatically once the proxy is ready ==="
echo "=== L2 login: username 'user', password 'live' ==="
wait_for_ssh
open_l1_shell
echo "=== L2 connected login: username 'user', password 'live' ==="
wait_for_session
teardown
