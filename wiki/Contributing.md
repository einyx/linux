# Contributing

We welcome contributions from everyone. This guide covers the process.

## Before You Start

### Legal

All contributions must be signed-off:
```bash
git commit -s
```

This indicates you agree to the [Developer Certificate of Origin](https://developercertificate.org/).

### Setup

Fork and clone:
```bash
# Fork on GitHub, then:
git clone https://github.com/YOUR_USERNAME/linux.git
cd linux
git remote add upstream https://github.com/einyx/linux.git
```

## Finding Work

**Easy tasks**:
- Look for `good first issue` label
- Documentation fixes
- Typos and cleanup
- Build warnings

**Regular work**:
- Bug reports without fixes
- TODO comments in code
- Performance improvements
- Security hardening

**Major work**:
- New drivers
- Core changes
- New features

Always check if someone's already working on it.

## Development Process

### 1. Create branch

```bash
git checkout -b descriptive-branch-name
```

Branch names:
- `fix/memory-leak-in-foo`
- `feature/add-bar-driver`
- `security/harden-baz`

### 2. Make changes

Follow the kernel coding style:
```c
static int example_function(void)
{
        struct example *e;
        int ret;

        e = kmalloc(sizeof(*e), GFP_KERNEL);
        if (!e)
                return -ENOMEM;

        ret = do_something(e);
        if (ret)
                goto err_free;

        return 0;

err_free:
        kfree(e);
        return ret;
}
```

Key points:
- 8-character tabs
- 80 column limit (soft)
- Braces on same line for functions
- Space after keywords (if, for, while)
- No space after function names

Check your style:
```bash
./scripts/checkpatch.pl --git HEAD
```

### 3. Test

**Build test**:
```bash
make -j$(nproc)
```

**Boot test** (if applicable):
```bash
qemu-system-x86_64 -kernel arch/x86/boot/bzImage -append "console=ttyS0" -nographic
```

**Run specific tests**:
```bash
# If you changed mm/
make M=mm
./tools/testing/selftests/mm/run_vmtests.sh
```

### 4. Commit

Write good commit messages:

```
subsystem: Short description (50 chars max)

Longer description explaining what this does and why.
Wrap at 72 characters. Be specific about the problem
being solved and how this fixes it.

If this fixes a bug, describe the symptoms and root
cause. Include relevant error messages.

Link: https://lore.kernel.org/link-to-discussion
Fixes: 123456789abc ("Previous commit this fixes")
Reported-by: Someone <someone@example.com>
Tested-by: Another <another@example.com>
Signed-off-by: Your Name <you@example.com>
```

Examples:
```bash
git commit -s -m "mm: fix use-after-free in page allocator

The page allocator could access freed memory when allocation
failed and cleanup was performed. This was due to improper
ordering of operations in the error path.

Fix by ensuring the memory is removed from lists before
freeing.

This was found by KASAN during stress testing:
  BUG: KASAN: use-after-free in free_pages_prepare+0x...

Fixes: abcdef123456 (\"mm: optimize page allocation\")
Signed-off-by: Your Name <you@example.com>"
```

### 5. Submit

Push and create PR:
```bash
git push origin your-branch
# Create PR on GitHub
```

PR description should include:
- What the change does
- Why it's needed
- How it was tested
- Any risks or side effects

## Code Review

### What to expect

- Automated checks run first (build, style, security)
- Human review within 48-72 hours
- May need several rounds of feedback
- Be patient and responsive

### Common feedback

**Style issues**: Fix with checkpatch
**Missing error handling**: Always check return values
**Memory leaks**: Ensure all allocations are freed
**Locking issues**: Document lock ordering
**Performance**: Provide benchmarks for optimizations

### Addressing feedback

```bash
# Make requested changes
git add -u
git commit --amend  # If updating existing commit

# Or add new commits
git commit -s -m "address review feedback"

# Force push
git push -f origin your-branch
```

## Tips

### DO:
- Start small
- One logical change per commit
- Test thoroughly
- Be responsive to feedback
- Read surrounding code first

### DON'T:
- Mix unrelated changes
- Break bisectability
- Ignore CI failures
- Take reviews personally
- Submit untested code

## Advanced Topics

### Patch series

For complex changes:
```bash
# Create series
git format-patch -3 --cover-letter

# Edit cover letter
vim 0000-cover-letter.patch

# Send (if using email workflow)
git send-email *.patch
```

### Backporting

For stable kernels:
```bash
# Cherry-pick to stable
git checkout linux-6.1.y
git cherry-pick -x <commit-sha>
# Add "Cc: stable@vger.kernel.org" to commit
```

### Becoming a maintainer

Regular contributors may be invited to become maintainers:
- Consistent quality contributions
- Good review feedback
- Understanding of subsystem
- Time to dedicate

## Getting Help

- **Questions**: [Discussions](https://github.com/einyx/linux/discussions)
- **Real-time**: IRC #kernel-community on Libera
- **Mentoring**: Ask in good first issue threads

## Recognition

All contributors are added to CREDITS file. Regular contributors may get:
- Reviewer rights
- Direct commit access
- Maintainer status

Thank you for contributing!