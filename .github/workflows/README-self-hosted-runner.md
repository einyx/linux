# Self-Hosted Runner Setup

If you're experiencing permission errors with self-hosted runners, follow these steps:

## 1. On the Runner Machine

Before starting the GitHub Actions runner service, run the setup script:

```bash
# Run as the user that will run the runner service
sudo ./scripts/setup-self-hosted-runner.sh
```

## 2. Configure Runner Environment

Edit the runner's `.env` file (in the actions-runner directory) and add:

```
RUNNER_TEMP=/tmp/runner-temp
RUNNER_TOOL_CACHE=/tmp/runner-tool-cache
RUNNER_WORKSPACE=/tmp/runner-workspace
```

## 3. Restart Runner Service

```bash
# If using systemd
sudo systemctl restart actions.runner.<org>-<repo>.<runner-name>.service

# Or if running manually
./run.sh
```

## Alternative: Use Docker

Consider running the self-hosted runner in a Docker container with proper volume mounts:

```bash
docker run -d \
  -v /tmp/runner-work:/tmp/runner-work \
  -v /tmp/runner-temp:/tmp/runner-temp \
  -v /tmp/runner-tool-cache:/tmp/runner-tool-cache \
  -e RUNNER_TEMP=/tmp/runner-temp \
  -e RUNNER_TOOL_CACHE=/tmp/runner-tool-cache \
  your-runner-image
```

## Troubleshooting

If you still see permission errors:

1. Check the runner service is running as a user with sudo privileges
2. Ensure SELinux or AppArmor isn't blocking directory creation
3. Check disk space on /tmp
4. Consider using GitHub-hosted runners for builds if self-hosted runners continue to have issues