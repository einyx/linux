# GitHub Wiki Content

This directory contains the content for the GitHub Wiki. To use these files:

## For Repository Maintainers

1. Clone the wiki repository:
```bash
git clone https://github.com/einyx/linux.wiki.git
```

2. Copy all .md files from this directory to the wiki repo:
```bash
cp wiki/*.md ../linux.wiki/
```

3. Commit and push to update the wiki:
```bash
cd ../linux.wiki
git add -A
git commit -m "Update wiki content"
git push
```

## For Contributors

To contribute to documentation:
1. Edit the .md files in this directory
2. Submit a PR with your changes
3. Wiki will be updated after merge

## Wiki Structure

- `Home.md` - Main wiki landing page
- `Getting-Started.md` - Quick start guide for new users
- `Security-Features.md` - Detailed security documentation
- `Contributing.md` - Contribution guidelines
- `Building-from-Source.md` - Build instructions

## Notes

- Wiki uses GitHub Flavored Markdown
- Internal links use `[[Page-Name]]` format
- Images go in `images/` subdirectory
- Keep filenames hyphenated (e.g., `Getting-Started.md`)