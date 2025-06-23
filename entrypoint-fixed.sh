#!/bin/bash
set -e

# Ensure work directory permissions are correct
if [ -n "${RUNNER_WORKDIR}" ]; then
    sudo mkdir -p ${RUNNER_WORKDIR}/_tool ${RUNNER_WORKDIR}/_temp ${RUNNER_WORKDIR}/_actions
    sudo chmod -R 777 ${RUNNER_WORKDIR}
    sudo chown -R runner:runner ${RUNNER_WORKDIR}
fi

# Ensure temp directories exist with correct permissions
sudo mkdir -p /tmp/runner-temp /tmp/runner-tool-cache
sudo chmod -R 777 /tmp/runner-temp /tmp/runner-tool-cache
sudo chown -R runner:runner /tmp/runner-temp /tmp/runner-tool-cache

if [ -z "${GITHUB_OWNER}" ] || [ -z "${GITHUB_REPOSITORY}" ]; then
    echo "Error: GITHUB_OWNER and GITHUB_REPOSITORY must be set"
    exit 1
fi

# Read PAT from .netrc
if [ -f ~/.netrc ]; then
    PAT=$(grep -A2 "machine github.com" ~/.netrc | grep password | awk '{print $2}')
    if [ -z "$PAT" ]; then
        echo "Error: No GitHub token found in .netrc"
        exit 1
    fi
else
    echo "Error: .netrc file not found"
    exit 1
fi

# Get registration token
echo "Getting registration token..."
REG_TOKEN=$(curl -sX POST \
    -H "Authorization: token ${PAT}" \
    -H "Accept: application/vnd.github.v3+json" \
    "https://api.github.com/repos/${GITHUB_OWNER}/${GITHUB_REPOSITORY}/actions/runners/registration-token" | jq -r .token)

if [ -z "$REG_TOKEN" ] || [ "$REG_TOKEN" == "null" ]; then
    echo "Error: Failed to get registration token"
    exit 1
fi

# Configure the runner
echo "Configuring runner..."
./config.sh \
    --url "https://github.com/${GITHUB_OWNER}/${GITHUB_REPOSITORY}" \
    --token "${REG_TOKEN}" \
    --name "${RUNNER_NAME}" \
    --work "${RUNNER_WORKDIR}" \
    --labels "${LABELS}" \
    --runnergroup "${RUNNER_GROUP}" \
    --unattended \
    --replace

# Cleanup function
cleanup() {
    echo "Removing runner..."
    ./config.sh remove --token "${REG_TOKEN}"
}

trap cleanup EXIT

# Start the runner
echo "Starting runner..."
./run.sh