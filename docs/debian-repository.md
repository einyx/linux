# Debian Repository

This project automatically builds and publishes Debian packages to a repository hosted on GitHub Pages.

## Repository URL

Once deployed, the repository will be available at:
```
https://<username>.github.io/<repository>/
```

## Adding the Repository

### Automatic Setup

```bash
wget -qO- https://<username>.github.io/<repository>/setup.sh | bash
```

### Manual Setup

1. Add the GPG key:
```bash
wget -qO - https://<username>.github.io/<repository>/repo-key.asc | sudo apt-key add -
```

2. Add the repository:
```bash
echo "deb https://<username>.github.io/<repository>/ stable main" | sudo tee /etc/apt/sources.list.d/kain-kernel.list
```

3. Update package list:
```bash
sudo apt update
```

4. Install packages:
```bash
sudo apt install linux-image-kain linux-headers-kain
```

## Available Distributions

- `stable` - Production releases (created from git tags)
- `testing` - Development builds (created from main branch)

## Building Locally

To create a local repository for testing:

```bash
# Initialize repository
./scripts/create-debian-repo.sh init

# Build kernel packages (if not already built)
make -j$(nproc) deb-pkg LOCALVERSION=-kain

# Add packages to repository
./scripts/create-debian-repo.sh add debian-repo ../ local

# Or create a simple repository
./scripts/create-debian-repo.sh simple simple-repo ../
```

## GitHub Actions Setup

The repository is automatically built and deployed by the `debian-repo.yml` workflow.

### Required Secrets (Optional)

- `GPG_PRIVATE_KEY` - GPG private key for signing packages (optional, will generate temporary key if not provided)

### Required Permissions

The workflow requires:
- Write access to GitHub Pages
- Contents read permission
- ID token write permission (for Pages deployment)

### Enabling GitHub Pages

1. Go to Settings → Pages
2. Set Source to "GitHub Actions"
3. The workflow will automatically deploy to Pages

## Package Naming

Packages are named following this convention:
- Release builds: `linux-image-<version>-kain_<version>_amd64.deb`
- Development builds: `linux-image-<version>-dev<date>-<commit>-kain_<version>_amd64.deb`

## Security Considerations

1. **Package Signing**: Packages are signed with GPG. Users should verify the key fingerprint.
2. **HTTPS Only**: The repository is served over HTTPS via GitHub Pages.
3. **Version Pinning**: Consider pinning specific versions in production.

## Troubleshooting

### GPG Key Issues

If you see GPG errors, ensure the key is properly imported:
```bash
gpg --list-keys
sudo apt-key list
```

### Repository Not Found

Ensure GitHub Pages is enabled and the workflow has completed successfully.

### Package Conflicts

Remove any conflicting kernel packages before installing:
```bash
sudo apt remove linux-image-generic linux-headers-generic
```

## Advanced Configuration

### Custom GPG Key

To use your own GPG key:

1. Export your private key:
```bash
gpg --export-secret-keys --armor YOUR_KEY_ID > private.key
```

2. Add it as a GitHub secret named `GPG_PRIVATE_KEY`

### Multiple Architectures

The workflow supports both amd64 and arm64. Modify the workflow to build for specific architectures.

### Custom Repository Structure

Edit `conf/distributions` in the workflow to customize:
- Components
- Architectures  
- Signing policies
- Package pools