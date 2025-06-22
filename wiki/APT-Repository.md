# APT Repository

Official Debian/Ubuntu repository for Kain kernel packages.

## Quick Setup

```bash
# Add repository key
wget -O - https://kain.example.com/kain-repo.asc | sudo apt-key add -

# Add repository
echo "deb https://kain.example.com stable main" | sudo tee /etc/apt/sources.list.d/kain.list

# Update and install
sudo apt update
sudo apt install linux-image-kain
```

## Repository Structure

```
/kain/
├── dists/
│   └── stable/
│       ├── Release
│       ├── Release.gpg
│       └── main/
│           ├── binary-amd64/
│           │   ├── Packages
│           │   └── Packages.gz
│           └── binary-arm64/
│               ├── Packages
│               └── Packages.gz
├── pool/
│   └── main/
│       ├── linux-image-6.16.0-*.deb
│       └── linux-headers-6.16.0-*.deb
└── kain-repo.asc (GPG public key)
```

## Available Packages

### linux-image-kain
- Latest kernel image
- Includes all security hardening
- Automatically updated

### linux-headers-kain
- Kernel headers for building modules
- Matches kernel version

### linux-image-kain-lts
- Long Term Support kernel (coming soon)
- Security updates only
- Stable for production

## Package Versions

Versions follow the format:
```
6.16.0-20240322-a1b2c3d4-1
│      │         │        └── Package revision
│      │         └────────── Git commit (short)
│      └──────────────────── Build date
└─────────────────────────── Kernel version
```

## Automatic Updates

Enable automatic security updates:
```bash
# Install unattended-upgrades
sudo apt install unattended-upgrades

# Configure for Kain kernel
echo 'Unattended-Upgrade::Origins-Pattern {
        "origin=Kain Community Kernel";
};' | sudo tee /etc/apt/apt.conf.d/51unattended-upgrades-kain
```

## Pin Priority

To always use Kain kernel over distribution kernel:
```bash
cat << EOF | sudo tee /etc/apt/preferences.d/kain-kernel
Package: linux-image-* linux-headers-*
Pin: origin kain.example.com
Pin-Priority: 1001
EOF
```

## Mirror Setup

Want to mirror our repository?

```bash
# Using apt-mirror
sudo apt install apt-mirror

# Configure /etc/apt/mirror.list
deb https://kain.example.com stable main

# Run mirror
sudo apt-mirror
```

## Troubleshooting

**GPG key errors**:
```bash
# Re-add key
wget -O - https://kain.example.com/kain-repo.asc | sudo apt-key add -
```

**404 errors**:
```bash
# Check repository URL
curl https://kain.example.com/dists/stable/Release

# Clear APT cache
sudo apt clean
sudo apt update
```

**Wrong architecture**:
```bash
# Check your architecture
dpkg --print-architecture

# Repository supports: amd64, arm64
```

## Building Your Own Repository

See [setup-debian-repo.sh](https://github.com/einyx/linux/blob/main/scripts/setup-debian-repo.sh) to create your own mirror.

## Security

- All packages are GPG signed
- SHA256 checksums in Release file
- HTTPS transport recommended
- Automatic security updates available

## API Access

Get package information programmatically:
```bash
# Latest package list
curl https://kain.example.com/package-index.json

# Package details
curl https://kain.example.com/dists/stable/main/binary-amd64/Packages
```