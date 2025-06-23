#!/bin/bash
# Setup script for self-hosted GitHub Actions runners
# This should be run on the runner machine before starting the runner service

echo "Setting up directories for GitHub Actions self-hosted runner..."

# Create required directories
sudo mkdir -p /tmp/runner-work/_tool
sudo mkdir -p /tmp/runner-work/_temp  
sudo mkdir -p /tmp/runner-work/_actions
sudo mkdir -p /tmp/runner-temp
sudo mkdir -p /tmp/runner-tool-cache

# Set permissions
sudo chmod -R 777 /tmp/runner-work
sudo chmod -R 777 /tmp/runner-temp
sudo chmod -R 777 /tmp/runner-tool-cache

# Create directories in runner home if needed
if [ -d "/home/runner" ]; then
    sudo mkdir -p /home/runner/work/_tool
    sudo mkdir -p /home/runner/work/_temp
    sudo mkdir -p /home/runner/work/_actions
    sudo chmod -R 777 /home/runner/work
    sudo chown -R runner:runner /home/runner/work
fi

# Ensure runner user owns tmp directories
RUNNER_USER="${RUNNER_USER:-runner}"
if id "$RUNNER_USER" &>/dev/null; then
    sudo chown -R $RUNNER_USER:$RUNNER_USER /tmp/runner-work /tmp/runner-temp /tmp/runner-tool-cache
fi

echo "Runner directories setup complete!"
echo ""
echo "You may also want to add these to the runner's .env file:"
echo "RUNNER_TEMP=/tmp/runner-temp"
echo "RUNNER_TOOL_CACHE=/tmp/runner-tool-cache"