#!/bin/bash
# Test GitHub Actions locally using act

set -e

echo "=== GitHub Actions Local Test ==="

# Check if act is installed
if ! command -v act &> /dev/null; then
    echo "Installing 'act' for local GitHub Actions testing..."
    
    # Install act
    if command -v brew &> /dev/null; then
        brew install act
    else
        # Install via script
        curl -s https://raw.githubusercontent.com/nektos/act/master/install.sh | sudo bash
    fi
fi

# Check Docker
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is required but not installed"
    echo "Install Docker: https://docs.docker.com/get-docker/"
    exit 1
fi

if ! docker ps &> /dev/null; then
    echo "Error: Docker daemon is not running"
    echo "Start Docker and try again"
    exit 1
fi

# List available workflows
echo ""
echo "Available workflows:"
ls -1 .github/workflows/*.yml | sed 's|.github/workflows/||' | sed 's|.yml||'

# Select workflow to test
if [ -z "$1" ]; then
    echo ""
    echo "Usage: $0 <workflow-name> [event]"
    echo "Example: $0 package push"
    echo ""
    echo "Or test all workflows: $0 all"
    exit 1
fi

WORKFLOW=$1
EVENT=${2:-push}

# Test specific workflow
test_workflow() {
    local workflow=$1
    local event=$2
    
    echo ""
    echo "Testing workflow: $workflow (event: $event)"
    echo "----------------------------------------"
    
    if [ -f ".github/workflows/${workflow}.yml" ]; then
        # Create act event file for testing
        if [ "$event" = "push" ]; then
            cat > /tmp/act-event.json << EOF
{
  "push": {
    "ref": "refs/heads/main",
    "repository": {
      "name": "linux",
      "owner": {
        "login": "einyx"
      }
    }
  }
}
EOF
        elif [ "$event" = "pull_request" ]; then
            cat > /tmp/act-event.json << EOF
{
  "pull_request": {
    "number": 123,
    "head": {
      "ref": "feature-branch",
      "sha": "abc123"
    },
    "base": {
      "ref": "main"
    }
  }
}
EOF
        fi
        
        # Run with act
        act -W ".github/workflows/${workflow}.yml" \
            -e /tmp/act-event.json \
            --container-architecture linux/amd64 \
            -P ubuntu-latest=catthehacker/ubuntu:act-latest \
            $event
        
        echo "✓ Workflow $workflow completed"
    else
        echo "✗ Workflow file not found: ${workflow}.yml"
        return 1
    fi
}

# Test all or specific workflow
if [ "$WORKFLOW" = "all" ]; then
    # Test all workflows
    for wf in .github/workflows/*.yml; do
        workflow=$(basename "$wf" .yml)
        test_workflow "$workflow" "$EVENT" || true
        echo ""
    done
else
    test_workflow "$WORKFLOW" "$EVENT"
fi

echo ""
echo "=== Test completed ==="
echo ""
echo "Note: Some workflows may fail locally due to:"
echo "- Missing secrets (GITHUB_TOKEN, etc)"
echo "- Docker limitations"
echo "- Network restrictions"
echo ""
echo "For full testing, push to a branch and check GitHub Actions tab"