#!/bin/bash

# IDOR Scanner Docker Wrapper
# Usage: ./idor-docker.sh [basic|results|logs|validate]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
IMAGE_NAME="idorscanner"

if [ ! -f "$SCRIPT_DIR/scope.json" ]; then
    echo "Error: scope.json not found in $SCRIPT_DIR"
    echo "Please create a scope.json file in the same directory as this script"
    exit 1
fi

show_usage() {
    echo "Usage: $0 [basic|results|logs|validate]"
    echo ""
    echo "Commands:"
    echo "  basic     - Basic scan (results stay in container)"
    echo "  results   - Scan with results accessible on host"
    echo "  logs      - Scan with logs and results accessible on host"
    echo "  validate  - Validate scope configuration"
    echo ""
    echo "Examples:"
    echo "  $0 basic"
    echo "  $0 results"
    echo "  $0 logs"
    echo "  $0 validate"
}

if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed or not in PATH"
    exit 1
fi

if ! docker image inspect "$IMAGE_NAME" &> /dev/null; then
    echo "Error: Docker image '$IMAGE_NAME' not found"
    echo "Please build the image first with: docker build -t $IMAGE_NAME ."
    exit 1
fi

case "${1:-}" in
    basic)
        echo "Running basic scan (results stay in container)..."
        docker run --rm \
            -v "$SCRIPT_DIR/scope.json:/app/scope.json" \
            "$IMAGE_NAME"
        ;;
    results)
        echo "Running scan with results accessible on host..."
        mkdir -p "$SCRIPT_DIR/results"
        docker run --rm \
            -v "$SCRIPT_DIR/scope.json:/app/scope.json" \
            -v "$SCRIPT_DIR/results:/app/results" \
            "$IMAGE_NAME"
        ;;
    logs)
        echo "Running scan with logs and results accessible on host..."
        mkdir -p "$SCRIPT_DIR/results"
        docker run --rm \
            -v "$SCRIPT_DIR/scope.json:/app/scope.json" \
            -v "$SCRIPT_DIR/results:/app/results" \
            -v /tmp:/tmp \
            "$IMAGE_NAME"
        ;;
    validate)
        echo "Validating scope configuration..."
        docker run --rm \
            -v "$SCRIPT_DIR/scope.json:/app/scope.json" \
            "$IMAGE_NAME" validate /app/scope.json
        ;;
    "")
        echo "Error: No command specified"
        echo ""
        show_usage
        exit 1
        ;;
    *)
        echo "Error: Unknown command '$1'"
        echo ""
        show_usage
        exit 1
        ;;
esac

echo "Done!"
