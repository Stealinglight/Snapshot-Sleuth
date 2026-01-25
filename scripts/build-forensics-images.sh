#!/bin/bash
#
# Build forensic tool Docker images
#
# Usage:
#   ./scripts/build-forensics-images.sh [options]
#
# Options:
#   --push          Push images to ECR after building
#   --tool <name>   Build only specific tool (yara, clamav, evidence-miner, log2timeline)
#   --tag <tag>     Custom tag (default: latest)
#   --region <aws>  AWS region (default: us-east-1)
#   --account <id>  AWS account ID (auto-detected if not provided)
#

set -euo pipefail

# Default values
PUSH=false
SPECIFIC_TOOL=""
TAG="latest"
REGION="${AWS_REGION:-us-east-1}"
ACCOUNT_ID="${AWS_ACCOUNT_ID:-}"
PROJECT_NAME="snapshot-sleuth"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Tools to build
TOOLS=("forensics-base" "yara" "clamav" "evidence-miner" "log2timeline")

# Parse arguments
while [[ $# -gt 0 ]]; do
  case $1 in
    --push)
      PUSH=true
      shift
      ;;
    --tool)
      SPECIFIC_TOOL="$2"
      shift 2
      ;;
    --tag)
      TAG="$2"
      shift 2
      ;;
    --region)
      REGION="$2"
      shift 2
      ;;
    --account)
      ACCOUNT_ID="$2"
      shift 2
      ;;
    --help)
      head -20 "$0" | tail -n +2 | sed 's/^# //'
      exit 0
      ;;
    *)
      echo -e "${RED}Unknown option: $1${NC}"
      exit 1
      ;;
  esac
done

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
LAMBDA_PY_DIR="$PROJECT_ROOT/packages/lambda-py"

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Snapshot Sleuth - Forensics Image Build${NC}"
echo -e "${GREEN}========================================${NC}"
echo ""

# Auto-detect AWS account ID if not provided
if [[ -z "$ACCOUNT_ID" ]]; then
  echo -e "${YELLOW}Auto-detecting AWS account ID...${NC}"
  ACCOUNT_ID=$(aws sts get-caller-identity --query Account --output text 2>/dev/null || echo "")
  if [[ -z "$ACCOUNT_ID" ]]; then
    echo -e "${RED}Could not auto-detect AWS account ID. Please provide --account or configure AWS credentials.${NC}"
    exit 1
  fi
fi

ECR_REGISTRY="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com"

echo "Configuration:"
echo "  Region:     $REGION"
echo "  Account:    $ACCOUNT_ID"
echo "  Registry:   $ECR_REGISTRY"
echo "  Tag:        $TAG"
echo "  Push:       $PUSH"
echo ""

# Login to ECR if pushing
if [[ "$PUSH" == "true" ]]; then
  echo -e "${YELLOW}Logging in to ECR...${NC}"
  aws ecr get-login-password --region "$REGION" | docker login --username AWS --password-stdin "$ECR_REGISTRY"
  echo ""
fi

# Build function
build_image() {
  local tool=$1
  local dockerfile_dir

  if [[ "$tool" == "forensics-base" ]]; then
    dockerfile_dir="$LAMBDA_PY_DIR/forensics-base"
  else
    dockerfile_dir="$LAMBDA_PY_DIR/${tool}-tool"
  fi

  local image_name="${PROJECT_NAME}/${tool}"
  local local_tag="${image_name}:${TAG}"
  local ecr_tag="${ECR_REGISTRY}/${image_name}:${TAG}"

  echo -e "${GREEN}Building $tool...${NC}"

  if [[ ! -d "$dockerfile_dir" ]]; then
    echo -e "${RED}Dockerfile directory not found: $dockerfile_dir${NC}"
    return 1
  fi

  # Build with BuildKit for better caching
  DOCKER_BUILDKIT=1 docker build \
    --file "$dockerfile_dir/Dockerfile" \
    --tag "$local_tag" \
    --build-arg BUILDKIT_INLINE_CACHE=1 \
    "$dockerfile_dir"

  echo -e "${GREEN}Built: $local_tag${NC}"

  # Push if requested
  if [[ "$PUSH" == "true" ]]; then
    echo -e "${YELLOW}Pushing to ECR...${NC}"
    docker tag "$local_tag" "$ecr_tag"
    docker push "$ecr_tag"
    echo -e "${GREEN}Pushed: $ecr_tag${NC}"
  fi

  echo ""
}

# Build images
if [[ -n "$SPECIFIC_TOOL" ]]; then
  # Build specific tool only
  if [[ "$SPECIFIC_TOOL" == "forensics-base" ]] || [[ " ${TOOLS[*]} " =~ " ${SPECIFIC_TOOL} " ]]; then
    build_image "$SPECIFIC_TOOL"
  else
    echo -e "${RED}Unknown tool: $SPECIFIC_TOOL${NC}"
    echo "Available tools: ${TOOLS[*]}"
    exit 1
  fi
else
  # Build all tools (base first, then others)
  for tool in "${TOOLS[@]}"; do
    build_image "$tool"
  done
fi

echo -e "${GREEN}========================================${NC}"
echo -e "${GREEN}Build complete!${NC}"
echo -e "${GREEN}========================================${NC}"

# Print summary
if [[ "$PUSH" == "true" ]]; then
  echo ""
  echo "Images pushed to ECR:"
  if [[ -n "$SPECIFIC_TOOL" ]]; then
    echo "  ${ECR_REGISTRY}/${PROJECT_NAME}/${SPECIFIC_TOOL}:${TAG}"
  else
    for tool in "${TOOLS[@]}"; do
      echo "  ${ECR_REGISTRY}/${PROJECT_NAME}/${tool}:${TAG}"
    done
  fi
fi
