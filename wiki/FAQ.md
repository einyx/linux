# FAQ

## General

**Q: What makes this different from mainline Linux?**
A: Security hardening by default, automated CI/CD, pre-built packages, and community-focused development. We merge upstream changes regularly.

**Q: Is this compatible with my distribution?**
A: Yes. It's a standard Linux kernel with additional hardening. Works anywhere mainline Linux works.

**Q: How often are releases made?**
A: Every commit to main branch triggers automated builds. Tagged releases follow upstream stable releases.

**Q: Can I use this in production?**
A: Yes, but test first. Many users run it in production. The hardening features are well-tested but may have compatibility issues with some workloads.

## Security

**Q: What security features are included?**
A: See [[Security Features]]. Key ones: KASLR, hardened usercopy, FORTIFY_SOURCE, stack protector, memory initialization.

**Q: Is this as secure as grsecurity?**
A: No. grsecurity has additional features we can't include. We implement what's available in mainline plus KSPP recommendations.

**Q: Do security features impact performance?**
A: Yes, typically 5-15% depending on workload. See performance section in [[Security Features]].

**Q: Can I disable security features?**
A: Yes, via boot parameters or rebuild. Example: `init_on_alloc=0 pti=off` (not recommended).

## Building

**Q: Build fails with "No rule to make target"**
A: Run `make mrproper` to clean, then reconfigure.

**Q: How much disk space needed?**
A: ~25GB for full build with debug symbols. ~5GB minimum.

**Q: Can I build on distribution X?**
A: If it can build mainline Linux, it can build this. See [[Building]] for dependencies.

**Q: Cross-compilation supported?**
A: Yes. See cross-compilation section in [[Building]].

## Installation

**Q: Will this replace my current kernel?**
A: No, installed alongside existing kernels. Select at boot via GRUB.

**Q: How to uninstall?**
A: Package manager: `sudo apt remove linux-image-VERSION` or `sudo dnf remove kernel-VERSION`
Manual: Remove files from /boot and update bootloader.

**Q: Breaks NVIDIA/proprietary drivers?**
A: Possibly. Rebuild drivers after installing. DKMS should handle automatically.

**Q: Can I dual boot with Windows?**
A: Yes, works normally. Security features don't affect other OSes.

## Troubleshooting

**Q: Boot hangs/panic after install**
A: Boot previous kernel from GRUB. Check [[Troubleshooting]] guide.

**Q: Module X not loading**
A: Likely not built. Rebuild with module enabled or use `make localmodconfig`.

**Q: Graphics issues/black screen**
A: Try `nomodeset` boot parameter. May need to disable some security features for proprietary drivers.

**Q: Network/WiFi not working**
A: Check if firmware needed: `dmesg | grep firmware`. Install linux-firmware package.

## Contributing

**Q: How to contribute?**
A: See [[Contributing]]. We welcome all contributions, especially security improvements.

**Q: Need kernel development experience?**
A: No. Documentation, testing, and bug reports are valuable too.

**Q: How long for PR review?**
A: Usually 48-72 hours for initial review. Security fixes prioritized.

**Q: Can I become a maintainer?**
A: Yes. Regular quality contributors are invited to join maintainer team.

## Performance

**Q: Why is it slower than mainline?**
A: Security features have overhead. See [[Security Features]] for impact details.

**Q: Can I optimize for my use case?**
A: Yes. Disable unneeded features, use localmodconfig, tune for your hardware.

**Q: Recommended for gaming?**
A: Yes, overhead is minimal (~2-5%). Some users report better stability.

**Q: Good for servers?**
A: Yes, especially security-sensitive ones. Test performance impact first.

## Packages

**Q: Which architectures supported?**
A: x86_64, ARM64 currently. More planned.

**Q: Package signing?**
A: Coming soon. For now, verify checksums from release page.

**Q: Can I request distribution X support?**
A: Open an issue. PRs for new package formats welcome.

**Q: How to get notified of updates?**
A: Watch the repository, subscribe to releases, or follow RSS feed.

## Advanced

**Q: Custom config migration?**
A: Copy your .config, then `make olddefconfig` to update.

**Q: Real-time (RT) patches?**
A: Not yet. Under consideration for future.

**Q: Support for architecture X?**
A: If mainline supports it, we can too. Open issue to request.

**Q: Commercial support available?**
A: No. Community support only via GitHub.

## Didn't find your answer?

- Search [existing issues](https://github.com/einyx/linux/issues)
- Ask in [Discussions](https://github.com/einyx/linux/discussions)
- IRC: #kernel-community on Libera.Chat