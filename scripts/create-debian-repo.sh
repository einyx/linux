#!/bin/bash
# Create a local Debian repository for testing

set -e

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date +'%H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
    exit 1
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check dependencies
check_deps() {
    local missing=()
    for cmd in reprepro gpg dpkg-scanpackages; do
        if ! command -v $cmd &> /dev/null; then
            missing+=($cmd)
        fi
    done
    
    if [ ${#missing[@]} -ne 0 ]; then
        error "Missing dependencies: ${missing[*]}\nInstall with: sudo apt-get install -y reprepro gnupg dpkg-dev"
    fi
}

# Create repository structure
create_repo() {
    local repo_dir="${1:-debian-repo}"
    
    log "Creating repository in $repo_dir..."
    
    mkdir -p "$repo_dir"/{conf,dists,pool/main}
    
    # Check for GPG key
    GPG_KEY_ID=$(gpg --list-secret-keys --keyid-format LONG 2>/dev/null | grep sec | head -1 | awk '{print $2}' | cut -d'/' -f2 || true)
    
    if [ -z "$GPG_KEY_ID" ]; then
        warning "No GPG key found, creating temporary key..."
        cat >gpg-batch <<EOF
%echo Generating temporary GPG key
%no-protection
Key-Type: RSA
Key-Length: 2048
Name-Real: Local Kain Kernel
Name-Email: local@kain-kernel.local
Expire-Date: 1y
%commit
%echo done
EOF
        gpg --batch --generate-key gpg-batch
        rm gpg-batch
        GPG_KEY_ID=$(gpg --list-secret-keys --keyid-format LONG | grep sec | head -1 | awk '{print $2}' | cut -d'/' -f2)
    fi
    
    log "Using GPG key: $GPG_KEY_ID"
    
    # Export public key
    gpg --armor --export "$GPG_KEY_ID" > "$repo_dir/repo-key.asc"
    
    # Create distributions file
    cat > "$repo_dir/conf/distributions" <<EOF
Origin: Kain Kernel
Label: Kain Kernel Local
Codename: local
Architectures: amd64 arm64 source
Components: main
Description: Local Kain Kernel Repository
SignWith: $GPG_KEY_ID

Origin: Kain Kernel
Label: Kain Kernel Local
Codename: stable
Architectures: amd64 arm64 source
Components: main
Description: Local Kain Kernel Stable Repository
SignWith: $GPG_KEY_ID

Origin: Kain Kernel
Label: Kain Kernel Local
Codename: testing
Architectures: amd64 arm64 source
Components: main
Description: Local Kain Kernel Testing Repository
SignWith: $GPG_KEY_ID
EOF

    # Create options file
    cat > "$repo_dir/conf/options" <<EOF
verbose
ask-passphrase
basedir .
EOF

    log "Repository structure created"
}

# Add packages to repository
add_packages() {
    local repo_dir="${1:-debian-repo}"
    local package_dir="${2:-.}"
    local dist="${3:-local}"
    
    if [ ! -d "$repo_dir/conf" ]; then
        error "Repository not initialized. Run with 'init' first."
    fi
    
    cd "$repo_dir"
    
    # Find all .deb files
    local debs=()
    if [ -d "$package_dir" ]; then
        mapfile -t debs < <(find "$package_dir" -name "*.deb" -type f)
    fi
    
    if [ ${#debs[@]} -eq 0 ]; then
        warning "No .deb files found in $package_dir"
        return
    fi
    
    log "Adding ${#debs[@]} packages to $dist distribution..."
    
    for deb in "${debs[@]}"; do
        log "Adding: $(basename "$deb")"
        reprepro includedeb "$dist" "$deb"
    done
    
    cd - > /dev/null
    log "Packages added successfully"
}

# Create repository index
create_index() {
    local repo_dir="${1:-debian-repo}"
    
    cat > "$repo_dir/index.html" <<'EOF'
<!DOCTYPE html>
<html>
<head>
    <title>Local Kain Kernel Repository</title>
    <style>
        body { font-family: sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        pre { background: #f4f4f4; padding: 10px; overflow-x: auto; }
        .section { margin: 20px 0; }
    </style>
</head>
<body>
    <h1>Local Kain Kernel Repository</h1>
    
    <div class="section">
        <h2>Setup Instructions</h2>
        <pre>
# Add the repository key
sudo apt-key add repo-key.asc

# Add repository to sources
echo "deb [trusted=yes] file://$(pwd) local main" | sudo tee /etc/apt/sources.list.d/kain-local.list

# Update and install
sudo apt update
sudo apt install linux-image-*-kain linux-headers-*-kain
        </pre>
    </div>
    
    <div class="section">
        <h2>Available Packages</h2>
        <p>Browse: <a href="pool/">pool/</a></p>
    </div>
    
    <div class="section">
        <h2>Repository Key</h2>
        <p><a href="repo-key.asc">repo-key.asc</a></p>
    </div>
</body>
</html>
EOF
}

# Simple repository without reprepro
create_simple_repo() {
    local repo_dir="${1:-debian-repo}"
    local package_dir="${2:-.}"
    
    log "Creating simple repository in $repo_dir..."
    
    mkdir -p "$repo_dir"
    
    # Copy all debs
    find "$package_dir" -name "*.deb" -exec cp {} "$repo_dir/" \;
    
    cd "$repo_dir"
    
    # Create Packages file
    dpkg-scanpackages . /dev/null > Packages
    gzip -c Packages > Packages.gz
    
    # Create Release file
    cat > Release <<EOF
Origin: Kain Kernel
Label: Kain Kernel Local
Suite: local
Codename: local
Components: main
Architectures: amd64 arm64
Date: $(date -R)
EOF
    
    # Add checksums
    echo "MD5Sum:" >> Release
    for f in Packages Packages.gz; do
        if [ -f "$f" ]; then
            echo " $(md5sum "$f" | awk '{print $1}') $(stat -c%s "$f") $f" >> Release
        fi
    done
    
    cd - > /dev/null
    
    create_index "$repo_dir"
    log "Simple repository created"
}

# Main
main() {
    local cmd="${1:-help}"
    shift || true
    
    case "$cmd" in
        init)
            check_deps
            create_repo "$@"
            ;;
        add)
            check_deps
            add_packages "$@"
            ;;
        simple)
            create_simple_repo "$@"
            ;;
        test)
            # Quick test
            check_deps
            create_repo "test-repo"
            echo "Test repository created in test-repo/"
            ;;
        help|*)
            cat <<EOF
Usage: $0 <command> [options]

Commands:
    init [repo-dir]                 Initialize a new repository
    add [repo-dir] [pkg-dir] [dist] Add packages to repository
    simple [repo-dir] [pkg-dir]     Create simple repository (no reprepro)
    test                           Create test repository
    help                           Show this help

Examples:
    $0 init                        # Create repository in debian-repo/
    $0 add debian-repo ../         # Add packages from parent directory
    $0 simple simple-repo ../      # Create simple repo without reprepro
EOF
            ;;
    esac
}

main "$@"