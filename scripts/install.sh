#!/bin/sh
# Epsilon Proxy installer
# Usage: curl -fsSL https://get.epsilon-data.org/install.sh | sh
#
# Installs epsilon-proxy and rathole binaries to /usr/local/bin
# Supports: Linux (amd64, arm64), macOS (amd64, arm64)

set -e

PROXY_VERSION="${EPSILON_PROXY_VERSION:-latest}"
RATHOLE_VERSION="${RATHOLE_VERSION:-0.5.0}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

GITHUB_REPO="Epsilon-Data/epsilon-proxy"
RATHOLE_REPO="rapiz1/rathole"

# Colors (only if terminal supports it)
if [ -t 1 ]; then
    GREEN='\033[0;32m'
    RED='\033[0;31m'
    YELLOW='\033[0;33m'
    NC='\033[0m'
else
    GREEN=''
    RED=''
    YELLOW=''
    NC=''
fi

info()  { printf "${GREEN}✓${NC} %s\n" "$1"; }
warn()  { printf "${YELLOW}!${NC} %s\n" "$1"; }
error() { printf "${RED}✗${NC} %s\n" "$1"; exit 1; }

# Detect OS and architecture
detect_platform() {
    OS="$(uname -s | tr '[:upper:]' '[:lower:]')"
    ARCH="$(uname -m)"

    case "$OS" in
        linux)  OS="linux" ;;
        darwin) OS="darwin" ;;
        *)      error "Unsupported OS: $OS" ;;
    esac

    case "$ARCH" in
        x86_64|amd64)   ARCH="amd64" ;;
        aarch64|arm64)  ARCH="arm64" ;;
        *)              error "Unsupported architecture: $ARCH" ;;
    esac

    # rathole uses different naming
    case "${OS}_${ARCH}" in
        linux_amd64)   RATHOLE_TARGET="x86_64-unknown-linux-musl" ;;
        linux_arm64)   RATHOLE_TARGET="aarch64-unknown-linux-musl" ;;
        darwin_amd64)  RATHOLE_TARGET="x86_64-apple-darwin" ;;
        darwin_arm64)  RATHOLE_TARGET="aarch64-apple-darwin" ;;
    esac

    printf "Platform: %s/%s\n" "$OS" "$ARCH"
}

# Check for required tools
check_deps() {
    for cmd in curl tar; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error "Required tool not found: $cmd"
        fi
    done
}

# Check write permissions
check_permissions() {
    if [ ! -d "$INSTALL_DIR" ]; then
        error "Install directory does not exist: $INSTALL_DIR"
    fi

    if [ ! -w "$INSTALL_DIR" ]; then
        if command -v sudo >/dev/null 2>&1; then
            warn "Need sudo to install to $INSTALL_DIR"
            SUDO="sudo"
        else
            error "Cannot write to $INSTALL_DIR and sudo is not available"
        fi
    else
        SUDO=""
    fi
}

# Install epsilon-proxy
install_proxy() {
    printf "\nInstalling epsilon-proxy...\n"

    if [ "$PROXY_VERSION" = "latest" ]; then
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/latest/download/epsilon-proxy_${OS}_${ARCH}.tar.gz"
    else
        DOWNLOAD_URL="https://github.com/${GITHUB_REPO}/releases/download/v${PROXY_VERSION}/epsilon-proxy_${PROXY_VERSION}_${OS}_${ARCH}.tar.gz"
    fi

    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    printf "  Downloading from GitHub... "
    if curl -fsSL "$DOWNLOAD_URL" -o "${TMP_DIR}/epsilon-proxy.tar.gz" 2>/dev/null; then
        printf "OK\n"
    else
        printf "FAILED\n"
        error "Download failed. Check if release exists at: $DOWNLOAD_URL"
    fi

    printf "  Extracting... "
    tar -xzf "${TMP_DIR}/epsilon-proxy.tar.gz" -C "$TMP_DIR"
    printf "OK\n"

    printf "  Installing to %s... " "$INSTALL_DIR"
    $SUDO install -m 755 "${TMP_DIR}/epsilon-proxy" "${INSTALL_DIR}/epsilon-proxy"
    printf "OK\n"

    info "epsilon-proxy installed: $(${INSTALL_DIR}/epsilon-proxy --version 2>/dev/null || echo 'OK')"
}

# Install rathole
install_rathole() {
    printf "\nInstalling rathole v%s...\n" "$RATHOLE_VERSION"

    if command -v rathole >/dev/null 2>&1; then
        EXISTING_VERSION=$(rathole --version 2>/dev/null | head -1 || echo "unknown")
        info "rathole already installed: $EXISTING_VERSION (skipping)"
        return
    fi

    RATHOLE_URL="https://github.com/${RATHOLE_REPO}/releases/download/v${RATHOLE_VERSION}/rathole-${RATHOLE_TARGET}.zip"

    TMP_DIR="$(mktemp -d)"

    printf "  Downloading... "
    if curl -fsSL "$RATHOLE_URL" -o "${TMP_DIR}/rathole.zip" 2>/dev/null; then
        printf "OK\n"
    else
        printf "FAILED\n"
        warn "Could not download rathole. You can install it manually."
        warn "Download from: https://github.com/rapiz1/rathole/releases"
        return
    fi

    printf "  Extracting... "
    if command -v unzip >/dev/null 2>&1; then
        unzip -q "${TMP_DIR}/rathole.zip" -d "$TMP_DIR"
    else
        warn "unzip not found. Install rathole manually from: https://github.com/rapiz1/rathole/releases"
        rm -rf "$TMP_DIR"
        return
    fi
    printf "OK\n"

    printf "  Installing to %s... " "$INSTALL_DIR"
    $SUDO install -m 755 "${TMP_DIR}/rathole" "${INSTALL_DIR}/rathole"
    printf "OK\n"

    rm -rf "$TMP_DIR"
    info "rathole installed: v${RATHOLE_VERSION}"
}

# Print next steps
print_next_steps() {
    printf "\n"
    printf "═══════════════════════════════════════════════════════════════\n"
    printf " Epsilon Proxy installed successfully!\n"
    printf "═══════════════════════════════════════════════════════════════\n"
    printf "\n"
    printf " Next steps:\n"
    printf "\n"
    printf "   1. Register with your Epsilon platform:\n"
    printf "\n"
    printf "      epsilon-proxy register \\\\\n"
    printf "        --token <your-token-from-epsilon-ui> \\\\\n"
    printf "        --api-url https://app.epsilon-data.org/api/v1/hub\n"
    printf "\n"
    printf "      You will be prompted for your database credentials.\n"
    printf "      Credentials are stored locally only — never sent to Epsilon.\n"
    printf "\n"
    printf "   2. Start the proxy:\n"
    printf "\n"
    printf "      epsilon-proxy start\n"
    printf "\n"
    printf " Documentation: https://github.com/Epsilon-Data/epsilon-proxy\n"
    printf "═══════════════════════════════════════════════════════════════\n"
}

# Main
main() {
    printf "\n"
    printf "Epsilon Proxy Installer\n"
    printf "───────────────────────\n"

    detect_platform
    check_deps
    check_permissions
    install_proxy
    install_rathole
    print_next_steps
}

main
