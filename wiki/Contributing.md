# Contributing Guide

Thank you for your interest in contributing to the Community Linux Kernel! We welcome contributions from everyone, regardless of experience level.

## 🌟 Ways to Contribute

### Code Contributions
- 🐛 **Bug Fixes** - Fix reported issues
- ✨ **Features** - Add new functionality
- 🔒 **Security** - Enhance security features
- ⚡ **Performance** - Optimize code
- 🧹 **Cleanup** - Refactor and improve

### Non-Code Contributions
- 📚 **Documentation** - Improve guides and comments
- 🧪 **Testing** - Test builds and report issues
- 🎨 **UI/UX** - Improve tools and scripts
- 🌍 **Translation** - Localize documentation
- 💬 **Support** - Help other users

## 🚀 Getting Started

### 1. Set Up Development Environment
```bash
# Fork the repository on GitHub first

# Clone your fork
git clone https://github.com/YOUR_USERNAME/linux.git
cd linux

# Add upstream remote
git remote add upstream https://github.com/einyx/linux.git

# Keep your fork updated
git fetch upstream
git checkout main
git merge upstream/main
```

### 2. Install Development Tools
```bash
# Debian/Ubuntu
sudo apt-get update
sudo apt-get install -y build-essential git bc kmod cpio flex bison \
  libssl-dev libelf-dev libncurses-dev

# Fedora/RHEL
sudo dnf install -y gcc make git bc openssl-devel elfutils-libelf-devel \
  ncurses-devel bison flex

# Install additional tools
pip install --user gitlint
```

### 3. Configure Git
```bash
# Set your identity
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"

# Enable commit signing (recommended)
git config --global commit.gpgSign true
```

## 📝 Contribution Process

### 1. Find Something to Work On

#### For Beginners
- Look for issues labeled `good first issue`
- Check `help wanted` labels
- Review `documentation` issues
- Start with small fixes

#### For Experienced
- Check the [roadmap](https://github.com/einyx/linux/projects)
- Look for `enhancement` issues
- Propose new features
- Work on performance improvements

### 2. Create a Branch
```bash
# Create feature branch
git checkout -b feature/your-feature-name

# Or for fixes
git checkout -b fix/issue-description
```

Branch naming:
- `feature/` - New features
- `fix/` - Bug fixes
- `security/` - Security improvements
- `docs/` - Documentation
- `test/` - Test improvements

### 3. Make Your Changes

#### Code Style
Follow the [Linux kernel coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html):

```c
/* Good */
static int example_function(struct example *ex)
{
        if (!ex)
                return -EINVAL;

        ex->value = 42;
        return 0;
}

/* Bad */
static int example_function(struct example* ex) {
    if(!ex) return -EINVAL;
    ex->value=42;
    return 0;
}
```

#### Run Style Checks
```bash
# Check your changes
./scripts/checkpatch.pl --git HEAD

# Fix common issues
./scripts/checkpatch.pl --fix-inplace
```

### 4. Test Your Changes

#### Basic Testing
```bash
# Build test
make defconfig
make -j$(nproc)

# Run specific tests
make M=drivers/your_driver

# Boot test (if applicable)
qemu-system-x86_64 -kernel arch/x86/boot/bzImage
```

#### Run CI Tests Locally
```bash
# Security checks
make C=2 CHECK="sparse -Wno-decl"

# Static analysis
cppcheck --enable=all kernel/your_file.c
```

### 5. Commit Your Changes

#### Commit Message Format
```
subsystem: Brief description (max 72 chars)

Detailed explanation of the change. Explain what the change
does and why it's needed. Wrap at 72 characters.

If fixing a bug, describe the bug and how this fixes it.
If adding a feature, explain the use case.

Fixes: #123
Signed-off-by: Your Name <your.email@example.com>
```

#### Example Commits
```bash
# Good commit
git commit -s -m "mm: fix memory leak in page allocation

The page allocator was not freeing memory in error paths,
causing a memory leak when allocation failed. This patch
adds proper cleanup in all error paths.

This was discovered during stress testing with low memory
conditions where the system would eventually OOM.

Fixes: #456
Signed-off-by: Jane Doe <jane@example.com>"

# Multiple commits for complex changes
git add mm/page_alloc.c
git commit -s -m "mm: refactor page allocation error handling"

git add mm/debug.c
git commit -s -m "mm: add debug output for allocation failures"
```

### 6. Push and Create PR

```bash
# Push to your fork
git push origin feature/your-feature-name

# Create PR via GitHub UI or CLI
gh pr create --title "mm: fix memory leak in page allocation" \
  --body "Description of changes..."
```

## ✅ PR Checklist

Before submitting:
- [ ] Code follows kernel style guide
- [ ] All commits are signed-off (`git commit -s`)
- [ ] Tests pass locally
- [ ] Documentation updated (if needed)
- [ ] No merge commits (rebase instead)
- [ ] PR description is clear
- [ ] Linked to issue (if applicable)

## 🤖 Automated Checks

Your PR will trigger:
1. **Style Check** - checkpatch.pl validation
2. **Build Test** - Multiple architectures
3. **Security Scan** - Static analysis
4. **Test Suite** - Automated tests

## 📋 Review Process

### What to Expect
1. Automated checks run first
2. Maintainers review within 48h
3. Address feedback promptly
4. May need multiple iterations
5. Merged after approval

### Review Criteria
- **Correctness** - Does it work?
- **Style** - Follows conventions?
- **Performance** - No regressions?
- **Security** - Safe and secure?
- **Documentation** - Well explained?

## 🎓 Tips for Success

### Do's ✅
- Start small for first contribution
- Ask questions if unsure
- Test thoroughly
- Be patient with reviews
- Learn from feedback

### Don'ts ❌
- Don't submit huge PRs
- Don't ignore CI failures
- Don't take reviews personally
- Don't skip documentation
- Don't break existing code

## 🛠️ Advanced Topics

### Working with Patches
```bash
# Create patch series
git format-patch -3 --cover-letter

# Apply patches
git am *.patch

# Send patches (if not using PRs)
git send-email *.patch
```

### Rebasing
```bash
# Update your branch
git fetch upstream
git rebase upstream/main

# Interactive rebase
git rebase -i upstream/main
```

### Co-authoring
```bash
# Credit co-authors
git commit -s -m "feature: add new driver

Co-authored-by: Other Dev <other@example.com>
Signed-off-by: Your Name <you@example.com>"
```

## 📚 Resources

### Documentation
- [[Development-Workflow]] - Our git workflow
- [[Coding-Standards]] - Detailed style guide
- [[Testing]] - Comprehensive testing
- [[Security-Contributing]] - Security patches

### External Links
- [Kernel Newbies](https://kernelnewbies.org/)
- [Linux Kernel Development](https://www.kernel.org/doc/html/latest/process/)
- [Git Documentation](https://git-scm.com/doc)

## 🤝 Getting Help

- **Discord**: [Join our server](https://discord.gg/example)
- **Discussions**: [GitHub Discussions](https://github.com/einyx/linux/discussions)
- **Email**: kernel-help@example.com

## 🏆 Recognition

We value all contributions:
- Contributors added to [CREDITS](../CREDITS)
- Regular contributors get merge rights
- Top contributors become maintainers

---

**Thank you for contributing! Together we're building a better, more secure kernel. 🚀**