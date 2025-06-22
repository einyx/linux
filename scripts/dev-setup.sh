#!/bin/bash
# Development environment setup script

set -e

echo "=== Linux Community Kernel Development Setup ==="
echo

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "Cannot detect OS"
    exit 1
fi

# Install dependencies based on OS
case $OS in
    ubuntu|debian)
        echo "Installing dependencies for Debian/Ubuntu..."
        sudo apt-get update
        sudo apt-get install -y \
            build-essential git bc kmod cpio flex bison \
            libssl-dev libelf-dev libncurses-dev \
            gcc-aarch64-linux-gnu \
            qemu-system-x86 qemu-system-arm \
            ccache sparse cppcheck \
            python3-pip python3-venv \
            curl wget vim tmux
        ;;
    
    fedora|rhel|centos)
        echo "Installing dependencies for Fedora/RHEL..."
        sudo dnf install -y \
            gcc make git bc openssl-devel elfutils-libelf-devel \
            ncurses-devel bison flex perl-ExtUtils-MakeMaker \
            gcc-aarch64-linux-gnu \
            qemu-system-x86 qemu-system-arm \
            ccache sparse cppcheck \
            python3-pip python3-virtualenv \
            curl wget vim tmux
        ;;
    
    arch)
        echo "Installing dependencies for Arch Linux..."
        sudo pacman -S --needed \
            base-devel git bc kmod cpio flex bison \
            openssl libelf ncurses \
            aarch64-linux-gnu-gcc \
            qemu qemu-arch-extra \
            ccache sparse cppcheck \
            python-pip python-virtualenv \
            curl wget vim tmux
        ;;
    
    *)
        echo "Unsupported OS: $OS"
        exit 1
        ;;
esac

# Setup git hooks
echo
echo "Setting up git hooks..."
cat > .git/hooks/pre-commit << 'EOF'
#!/bin/bash
# Pre-commit hook for kernel development

# Run checkpatch on staged files
ERRORS=0
for file in $(git diff --cached --name-only | grep -E '\.[ch]$'); do
    if [ -f "$file" ]; then
        ./scripts/checkpatch.pl --no-signoff -f "$file" || ERRORS=$((ERRORS + 1))
    fi
done

if [ $ERRORS -gt 0 ]; then
    echo "Fix style errors before committing"
    exit 1
fi
EOF
chmod +x .git/hooks/pre-commit

# Setup ccache
echo
echo "Setting up ccache..."
mkdir -p ~/.ccache
cat > ~/.ccache/ccache.conf << EOF
max_size = 5G
compression = true
EOF

# Create useful aliases
echo
echo "Creating development aliases..."
cat >> ~/.bashrc << 'EOF'

# Kernel development aliases
alias kbuild='make -j$(nproc)'
alias kconfig='make menuconfig'
alias kclean='make clean'
alias kmrproper='make mrproper'
alias ktest='make kselftest'
alias kdebug='scripts/decode_stacktrace.sh'
alias kcheck='./scripts/checkpatch.pl --git HEAD'

# Enable ccache
export PATH="/usr/lib/ccache:$PATH"

EOF

# Setup kernel debugging
echo
echo "Setting up kernel debugging..."
cat > ~/.gdbinit << 'EOF'
# GDB settings for kernel debugging
set auto-load safe-path /
add-auto-load-safe-path ./scripts/gdb/
source ./scripts/gdb/vmlinux-gdb.py
EOF

# Create development directories
echo
echo "Creating development directories..."
mkdir -p ~/kernel/{builds,configs,patches}

# Download useful configs
echo
echo "Downloading useful kernel configs..."
cd ~/kernel/configs
wget -q https://raw.githubusercontent.com/ClangBuiltLinux/continuous-integration2/main/configs/x86_64.config
wget -q https://kernsec.org/files/kernel-hardening-checker/kconfig-hardened-check.py
chmod +x kconfig-hardened-check.py
cd - > /dev/null

# Setup Python environment
echo
echo "Setting up Python environment..."
python3 -m venv ~/kernel/venv
~/kernel/venv/bin/pip install --upgrade pip
~/kernel/venv/bin/pip install \
    GitPython matplotlib pandas \
    requests beautifulsoup4

# Create quick start script
cat > ~/kernel/quickstart.sh << 'EOF'
#!/bin/bash
echo "Linux Community Kernel Quick Commands:"
echo
echo "  kbuild        - Build kernel with all cores"
echo "  kconfig       - Configure kernel (menuconfig)"
echo "  kclean        - Clean build"
echo "  kcheck        - Check your commits with checkpatch"
echo "  make help     - Show all make targets"
echo
echo "First time setup:"
echo "  1. make defconfig    # Start with defaults"
echo "  2. kconfig           # Customize"
echo "  3. kbuild            # Build"
echo
echo "Testing:"
echo "  make kselftest       # Run kernel selftests"
echo "  make htmldocs        # Build documentation"
EOF
chmod +x ~/kernel/quickstart.sh

echo
echo "=== Setup Complete ==="
echo
echo "Next steps:"
echo "1. Source your shell: source ~/.bashrc"
echo "2. Run ~/kernel/quickstart.sh for quick reference"
echo "3. Start hacking!"
echo
echo "Join our community:"
echo "- GitHub Discussions: https://github.com/einyx/linux/discussions"
echo "- Report bugs: https://github.com/einyx/linux/issues"
echo