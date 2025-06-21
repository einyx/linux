#!/bin/bash
# Build packages for Security Hardening LSM

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_DIR/build"
VERSION="1.0.0"

echo "Building Security Hardening LSM packages..."
echo "Project: $PROJECT_DIR"
echo "Version: $VERSION"

# Clean build directory
rm -rf "$BUILD_DIR"
mkdir -p "$BUILD_DIR"

# Build Debian package
echo -e "\n=== Building Debian Package ==="
cd "$BUILD_DIR"
mkdir -p debian-build/hardening-lsm-$VERSION
rsync -av --exclude='build' --exclude='.git' "$PROJECT_DIR"/ debian-build/hardening-lsm-$VERSION/
cd debian-build/hardening-lsm-$VERSION

# Copy debian directory to root for dpkg-buildpackage
cp -r packaging/debian .
# Use simple rules file if debhelper not available
if ! command -v dh >/dev/null 2>&1; then
    cp packaging/debian/rules.simple debian/rules
    chmod +x debian/rules
fi

# Create source tarball
tar czf "../hardening-lsm_$VERSION.orig.tar.gz" \
    --exclude=build --exclude=.git --exclude="*.o" .

# Build package
if command -v dpkg-buildpackage >/dev/null 2>&1; then
    dpkg-buildpackage -us -uc -d 2>&1 | tee build.log
    if [ -f ../hardening-lsm*.deb ] || ls ../hardening-lsm*.deb >/dev/null 2>&1; then
        echo "✓ Debian package built successfully"
        ls -la ../hardening-lsm*.deb
    else
        echo "⚠ Package build had warnings but may have succeeded"
        find .. -name "*.deb" -exec ls -la {} \;
    fi
else
    echo "⚠ dpkg-buildpackage not available, skipping Debian build"
fi

# Build RPM package
echo -e "\n=== Building RPM Package ==="
cd "$BUILD_DIR"
if command -v rpmbuild >/dev/null 2>&1; then
    mkdir -p rpm-build/{SOURCES,SPECS,BUILD,RPMS,SRPMS}
    rsync -av --exclude='build' --exclude='.git' "$PROJECT_DIR"/ rpm-build/SOURCES/hardening-lsm-$VERSION/
    tar czf "rpm-build/SOURCES/hardening-lsm-$VERSION.tar.gz" \
        -C rpm-build/SOURCES hardening-lsm-$VERSION
    
    cp "$PROJECT_DIR/packaging/rpm/hardening-lsm.spec" rpm-build/SPECS/
    
    rpmbuild --define "_topdir $(pwd)/rpm-build" \
             -ba rpm-build/SPECS/hardening-lsm.spec
    
    echo "✓ RPM package built successfully"
    find rpm-build/RPMS -name "*.rpm" -exec ls -la {} \;
else
    echo "⚠ rpmbuild not available, skipping RPM build"
fi

# Build Arch package
echo -e "\n=== Building Arch Package ==="
cd "$BUILD_DIR"
if command -v makepkg >/dev/null 2>&1; then
    mkdir -p arch-build
    rsync -av --exclude='build' --exclude='.git' "$PROJECT_DIR"/ arch-build/hardening-lsm-$VERSION/
    tar czf "arch-build/hardening-lsm-$VERSION.tar.gz" \
        -C arch-build hardening-lsm-$VERSION
    
    cd arch-build
    cp "$PROJECT_DIR/packaging/arch/PKGBUILD" .
    cp "$PROJECT_DIR/packaging/arch/hardening-lsm.install" .
    
    makepkg -s --noconfirm
    echo "✓ Arch package built successfully"
    ls -la *.pkg.tar.*
else
    echo "⚠ makepkg not available, skipping Arch build"
fi

# Create source distribution
echo -e "\n=== Creating Source Distribution ==="
cd "$BUILD_DIR"
mkdir -p source-dist
rsync -av --exclude='build' --exclude='.git' "$PROJECT_DIR"/ source-dist/hardening-lsm-$VERSION/
cd source-dist

# Clean up unnecessary files
find hardening-lsm-$VERSION -name ".git" -type d -exec rm -rf {} + 2>/dev/null || true
find hardening-lsm-$VERSION -name "*.o" -delete
find hardening-lsm-$VERSION -name "build" -type d -exec rm -rf {} + 2>/dev/null || true

# Create tarballs
tar czf "hardening-lsm-$VERSION.tar.gz" hardening-lsm-$VERSION
tar cJf "hardening-lsm-$VERSION.tar.xz" hardening-lsm-$VERSION
zip -r "hardening-lsm-$VERSION.zip" hardening-lsm-$VERSION >/dev/null

echo "✓ Source distribution created"
ls -la hardening-lsm-$VERSION.*

echo -e "\n=== Build Summary ==="
echo "All packages built in: $BUILD_DIR"
echo ""
echo "Available packages:"
find "$BUILD_DIR" -name "*.deb" -o -name "*.rpm" -o -name "*.pkg.tar.*" \
     -o -name "*.tar.gz" -o -name "*.tar.xz" -o -name "*.zip" | \
     sort | sed 's/^/  /'

echo -e "\n✅ Package building complete!"