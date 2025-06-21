#!/bin/bash
# Security Hardening LSM Installation Script

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULE_NAME="hardening-lsm"
VERSION="1.0.0"

# Detect distribution
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
    else
        echo -e "${RED}Cannot detect distribution${NC}"
        exit 1
    fi
}

# Check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then
        echo -e "${RED}This script must be run as root${NC}"
        echo "Please run: sudo $0"
        exit 1
    fi
}

# Install dependencies
install_dependencies() {
    echo -e "${BLUE}Installing dependencies...${NC}"
    
    case $DISTRO in
        ubuntu|debian)
            apt-get update
            apt-get install -y dkms linux-headers-$(uname -r) build-essential
            ;;
        fedora|rhel|centos)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y dkms kernel-devel gcc make
            else
                yum install -y dkms kernel-devel gcc make
            fi
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm dkms linux-headers base-devel
            ;;
        opensuse*)
            zypper install -y dkms kernel-devel gcc make
            ;;
        *)
            echo -e "${YELLOW}Unknown distribution. Please install manually:${NC}"
            echo "  - DKMS"
            echo "  - Kernel headers"
            echo "  - Build tools (gcc, make)"
            read -p "Continue anyway? (y/N): " -n 1 -r
            echo
            if [[ ! $REPLY =~ ^[Yy]$ ]]; then
                exit 1
            fi
            ;;
    esac
}

# Install kernel module
install_module() {
    echo -e "${BLUE}Installing Security Hardening LSM...${NC}"
    
    # Copy source to DKMS location
    DKMS_DIR="/usr/src/$MODULE_NAME-$VERSION"
    mkdir -p "$DKMS_DIR"
    cp -r "$SCRIPT_DIR"/* "$DKMS_DIR/"
    
    # Copy DKMS configuration
    cp "$SCRIPT_DIR/packaging/dkms/dkms.conf" "$DKMS_DIR/"
    
    # Add to DKMS
    dkms add -m "$MODULE_NAME" -v "$VERSION"
    
    # Build module
    echo -e "${BLUE}Building module...${NC}"
    dkms build -m "$MODULE_NAME" -v "$VERSION"
    
    # Install module
    echo -e "${BLUE}Installing module...${NC}"
    dkms install -m "$MODULE_NAME" -v "$VERSION"
}

# Install userspace tools
install_tools() {
    echo -e "${BLUE}Installing management tools...${NC}"
    
    # Install tools
    cp "$SCRIPT_DIR/tools/hardening-ctl" /usr/bin/
    cp "$SCRIPT_DIR/tools/hardening-status" /usr/bin/
    cp "$SCRIPT_DIR/tools/hardening-profiles" /usr/bin/
    chmod +x /usr/bin/hardening-*
    
    # Install systemd service
    if [ -d /lib/systemd/system ]; then
        cp "$SCRIPT_DIR/packaging/systemd/hardening-lsm.service" /lib/systemd/system/
        systemctl daemon-reload
        systemctl enable hardening-lsm.service
    fi
    
    # Create config directories
    mkdir -p /etc/hardening-lsm/profiles
    
    # Install example profiles
    cp "$SCRIPT_DIR/examples"/*.json /etc/hardening-lsm/profiles/
}

# Configure bootloader
configure_bootloader() {
    echo -e "${BLUE}Configuring bootloader...${NC}"
    
    # Check if hardening is already in LSM list
    if ! grep -q "hardening" /etc/default/grub 2>/dev/null; then
        echo -e "${YELLOW}Adding hardening to kernel LSM list...${NC}"
        
        # Add to GRUB configuration
        if [ -f /etc/default/grub ]; then
            # Backup original
            cp /etc/default/grub /etc/default/grub.backup
            
            # Add hardening to LSM list
            if grep -q "lsm=" /etc/default/grub; then
                # LSM list exists, add hardening
                sed -i 's/lsm=\([^"]*\)/lsm=\1,hardening/' /etc/default/grub
            else
                # No LSM list, create one
                sed -i 's/\(GRUB_CMDLINE_LINUX_DEFAULT="[^"]*\)"/\1 lsm=landlock,lockdown,yama,loadpin,safesetid,hardening,selinux,apparmor"/' /etc/default/grub
            fi
            
            # Update GRUB
            if command -v update-grub >/dev/null 2>&1; then
                update-grub
            elif command -v grub2-mkconfig >/dev/null 2>&1; then
                grub2-mkconfig -o /boot/grub2/grub.cfg
            elif command -v grub-mkconfig >/dev/null 2>&1; then
                grub-mkconfig -o /boot/grub/grub.cfg
            else
                echo -e "${YELLOW}Could not update GRUB automatically${NC}"
                echo "Please add 'lsm=...,hardening,...' to your kernel command line"
            fi
        fi
    else
        echo -e "${GREEN}Hardening already configured in bootloader${NC}"
    fi
}

# Show status
show_status() {
    echo -e "\n${GREEN}=== Installation Complete ===${NC}"
    echo -e "${BLUE}Security Hardening LSM has been installed${NC}"
    echo ""
    echo "Next steps:"
    echo "  1. Reboot your system to activate the module"
    echo "  2. Check status: hardening-status"
    echo "  3. Configure profiles: hardening-profiles list"
    echo "  4. Control module: hardening-ctl --help"
    echo ""
    echo "Documentation: /usr/share/doc/hardening-lsm/"
    echo ""
    
    # Check if module can be loaded now
    if modinfo hardening >/dev/null 2>&1; then
        echo -e "${GREEN}✓ Module is available for loading${NC}"
    else
        echo -e "${YELLOW}⚠ Module will be available after reboot${NC}"
    fi
}

# Uninstall function
uninstall() {
    echo -e "${YELLOW}Uninstalling Security Hardening LSM...${NC}"
    
    # Stop service
    if systemctl is-enabled hardening-lsm.service >/dev/null 2>&1; then
        systemctl stop hardening-lsm.service
        systemctl disable hardening-lsm.service
    fi
    
    # Remove from DKMS
    if dkms status | grep -q "$MODULE_NAME"; then
        dkms remove -m "$MODULE_NAME" -v "$VERSION" --all
    fi
    
    # Remove files
    rm -f /usr/bin/hardening-*
    rm -f /lib/systemd/system/hardening-lsm.service
    rm -rf "/usr/src/$MODULE_NAME-$VERSION"
    
    # Remove from GRUB (optional)
    read -p "Remove from bootloader configuration? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        if [ -f /etc/default/grub.backup ]; then
            mv /etc/default/grub.backup /etc/default/grub
        else
            sed -i 's/,hardening//g' /etc/default/grub
        fi
        
        if command -v update-grub >/dev/null 2>&1; then
            update-grub
        elif command -v grub2-mkconfig >/dev/null 2>&1; then
            grub2-mkconfig -o /boot/grub2/grub.cfg
        fi
    fi
    
    echo -e "${GREEN}Uninstallation complete${NC}"
}

# Main function
main() {
    echo -e "${BLUE}Security Hardening LSM Installer${NC}"
    echo -e "${BLUE}================================${NC}"
    echo ""
    
    # Parse command line arguments
    case "${1:-install}" in
        install)
            detect_distro
            check_root
            echo -e "Detected: ${GREEN}$DISTRO $DISTRO_VERSION${NC}"
            echo ""
            
            install_dependencies
            install_module
            install_tools
            configure_bootloader
            show_status
            ;;
        uninstall)
            check_root
            uninstall
            ;;
        *)
            echo "Usage: $0 [install|uninstall]"
            exit 1
            ;;
    esac
}

# Run main function
main "$@"