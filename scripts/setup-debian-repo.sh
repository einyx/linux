#!/bin/bash
# Setup Debian repository for Kain kernel packages

set -e

REPO_BASE="/var/www/html/kain"
REPO_NAME="Kain Community Kernel"
REPO_CODENAME="stable"
REPO_ARCHITECTURES="amd64 arm64"

echo "=== Setting up Debian Repository for Kain Kernel ==="
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "This script must be run as root (use sudo)"
    exit 1
fi

# Install required packages
echo "Installing required packages..."
apt-get update
apt-get install -y dpkg-dev apt-utils gnupg2 apache2

# Create repository structure
echo "Creating repository structure..."
mkdir -p ${REPO_BASE}/{pool/main,dists/${REPO_CODENAME}/main/binary-{amd64,arm64}}
mkdir -p ${REPO_BASE}/conf

# Create repository configuration
echo "Creating repository configuration..."
cat > ${REPO_BASE}/conf/distributions << EOF
Origin: ${REPO_NAME}
Label: ${REPO_NAME}
Codename: ${REPO_CODENAME}
Architectures: ${REPO_ARCHITECTURES}
Components: main
Description: Community-driven security-focused Linux kernel
SignWith: yes
EOF

# Generate GPG key for signing
echo "Generating GPG key for repository signing..."
cat > /tmp/gpg-batch << EOF
%echo Generating GPG key for Kain Kernel Repository
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: Kain Kernel Repository
Name-Email: kain@localhost
Expire-Date: 2y
%no-protection
%commit
%echo done
EOF

export GNUPGHOME=${REPO_BASE}/.gnupg
mkdir -p $GNUPGHOME
chmod 700 $GNUPGHOME

gpg --batch --generate-key /tmp/gpg-batch
rm -f /tmp/gpg-batch

# Export public key
echo "Exporting public key..."
gpg --armor --export > ${REPO_BASE}/kain-repo.asc

# Create repository management scripts
echo "Creating repository management scripts..."

# Script to add packages
cat > ${REPO_BASE}/add-package.sh << 'SCRIPT'
#!/bin/bash
# Add a package to the Kain repository

if [ $# -ne 1 ]; then
    echo "Usage: $0 <package.deb>"
    exit 1
fi

PACKAGE=$1
REPO_BASE="/var/www/html/kain"

if [ ! -f "$PACKAGE" ]; then
    echo "Error: Package file not found: $PACKAGE"
    exit 1
fi

# Extract package info
ARCH=$(dpkg-deb -f "$PACKAGE" Architecture)
PACKAGE_NAME=$(dpkg-deb -f "$PACKAGE" Package)

# Copy to pool
echo "Adding $PACKAGE_NAME to repository..."
cp "$PACKAGE" ${REPO_BASE}/pool/main/

# Update repository metadata
cd ${REPO_BASE}
dpkg-scanpackages pool/main > dists/stable/main/binary-${ARCH}/Packages
gzip -9c dists/stable/main/binary-${ARCH}/Packages > dists/stable/main/binary-${ARCH}/Packages.gz

# Generate Release file
cd dists/stable
cat > Release << EOF
Origin: Kain Community Kernel
Label: Kain Community Kernel
Suite: stable
Codename: stable
Version: 1.0
Architectures: amd64 arm64
Components: main
Description: Community-driven security-focused Linux kernel
Date: $(date -R)
EOF

# Add checksums
echo "MD5Sum:" >> Release
for file in main/binary-*/Packages*; do
    size=$(stat -c%s "$file")
    md5=$(md5sum "$file" | cut -d' ' -f1)
    echo " $md5 $size $file" >> Release
done

echo "SHA256:" >> Release
for file in main/binary-*/Packages*; do
    size=$(stat -c%s "$file")
    sha256=$(sha256sum "$file" | cut -d' ' -f1)
    echo " $sha256 $size $file" >> Release
done

# Sign Release file
export GNUPGHOME=${REPO_BASE}/.gnupg
gpg --default-key kain@localhost --clearsign -o InRelease Release
gpg --default-key kain@localhost -abs -o Release.gpg Release

echo "Package added successfully!"
SCRIPT

chmod +x ${REPO_BASE}/add-package.sh

# Script to update from GitHub releases
cat > ${REPO_BASE}/update-from-github.sh << 'SCRIPT'
#!/bin/bash
# Update repository from GitHub releases

REPO_BASE="/var/www/html/kain"
GITHUB_REPO="einyx/linux"
TEMP_DIR=$(mktemp -d)

echo "Fetching latest releases from GitHub..."

# Get latest release info
LATEST_RELEASE=$(curl -s https://api.github.com/repos/${GITHUB_REPO}/releases/latest)
RELEASE_TAG=$(echo "$LATEST_RELEASE" | grep -oP '"tag_name": "\K[^"]+')

echo "Latest release: $RELEASE_TAG"

# Download DEB packages
cd $TEMP_DIR
curl -s https://api.github.com/repos/${GITHUB_REPO}/releases/latest | \
    grep -oP '"browser_download_url": "\K[^"]+\.deb' | \
    while read url; do
        echo "Downloading $(basename $url)..."
        wget -q "$url"
    done

# Add all downloaded packages
for deb in *.deb; do
    if [ -f "$deb" ]; then
        ${REPO_BASE}/add-package.sh "$deb"
    fi
done

# Cleanup
rm -rf $TEMP_DIR

echo "Repository updated!"
SCRIPT

chmod +x ${REPO_BASE}/update-from-github.sh

# Create Apache configuration
echo "Configuring Apache..."
cat > /etc/apache2/sites-available/kain-repo.conf << 'APACHE'
<VirtualHost *:80>
    ServerName kain.example.com
    DocumentRoot /var/www/html/kain
    
    <Directory /var/www/html/kain>
        Options Indexes FollowSymLinks
        AllowOverride None
        Require all granted
    </Directory>
    
    # Enable directory listings
    <Directory /var/www/html/kain/pool>
        Options +Indexes
    </Directory>
    
    ErrorLog ${APACHE_LOG_DIR}/kain-repo-error.log
    CustomLog ${APACHE_LOG_DIR}/kain-repo-access.log combined
</VirtualHost>
APACHE

# Create index page
cat > ${REPO_BASE}/index.html << 'HTML'
<!DOCTYPE html>
<html>
<head>
    <title>Kain Community Kernel Repository</title>
    <style>
        body { font-family: monospace; max-width: 800px; margin: 0 auto; padding: 20px; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        h1, h2 { color: #333; }
    </style>
</head>
<body>
    <h1>Kain Community Kernel Repository</h1>
    <p>Security-focused Linux kernel with automated builds</p>
    
    <h2>Add Repository</h2>
    <pre>
# Download and add GPG key
wget -O - http://YOUR_SERVER/kain/kain-repo.asc | sudo apt-key add -

# Add repository
echo "deb http://YOUR_SERVER/kain stable main" | sudo tee /etc/apt/sources.list.d/kain.list

# Update and install
sudo apt update
sudo apt install linux-image-kain
    </pre>
    
    <h2>Browse</h2>
    <ul>
        <li><a href="/kain/pool/">Package Pool</a></li>
        <li><a href="/kain/dists/">Distributions</a></li>
        <li><a href="/kain/kain-repo.asc">GPG Key</a></li>
    </ul>
    
    <h2>Source</h2>
    <p><a href="https://github.com/einyx/linux">GitHub Repository</a></p>
</body>
</html>
HTML

# Set permissions
chown -R www-data:www-data ${REPO_BASE}

# Create systemd service for automatic updates
cat > /etc/systemd/system/kain-repo-update.service << 'SYSTEMD'
[Unit]
Description=Update Kain Kernel Repository
After=network.target

[Service]
Type=oneshot
ExecStart=/var/www/html/kain/update-from-github.sh
User=root
SYSTEMD

cat > /etc/systemd/system/kain-repo-update.timer << 'SYSTEMD'
[Unit]
Description=Update Kain Kernel Repository daily
Requires=kain-repo-update.service

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
SYSTEMD

# Create client configuration script
cat > ${REPO_BASE}/setup-client.sh << 'CLIENT'
#!/bin/bash
# Setup Kain repository on client system

REPO_URL="${1:-http://localhost/kain}"

echo "Setting up Kain kernel repository..."

# Add GPG key
wget -O - ${REPO_URL}/kain-repo.asc | sudo apt-key add -

# Add repository
echo "deb ${REPO_URL} stable main" | sudo tee /etc/apt/sources.list.d/kain.list

# Create APT preferences to prioritize Kain kernel
sudo tee /etc/apt/preferences.d/kain-kernel << EOF
Package: linux-image-* linux-headers-*
Pin: origin ${REPO_URL#http://}
Pin-Priority: 1001
EOF

# Update package list
sudo apt update

echo "Repository added! Install kernel with:"
echo "  sudo apt install linux-image-kain"
CLIENT

chmod +x ${REPO_BASE}/setup-client.sh

echo
echo "=== Repository Setup Complete ==="
echo
echo "Repository location: ${REPO_BASE}"
echo "GPG key: ${REPO_BASE}/kain-repo.asc"
echo
echo "To enable the repository in Apache:"
echo "  a2ensite kain-repo"
echo "  systemctl reload apache2"
echo
echo "To add packages:"
echo "  ${REPO_BASE}/add-package.sh <package.deb>"
echo
echo "To update from GitHub:"
echo "  ${REPO_BASE}/update-from-github.sh"
echo
echo "To enable automatic updates:"
echo "  systemctl enable --now kain-repo-update.timer"
echo
echo "Client setup:"
echo "  wget -O - http://YOUR_SERVER/kain/setup-client.sh | bash"