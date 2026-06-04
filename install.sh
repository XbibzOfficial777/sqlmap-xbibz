#!/usr/bin/env bash
# =============================================================================
# Recoded By Xbibz Official
# sqlmap Auto-Installer - curl-friendly one-liner installation
# Supports: Linux, macOS, Termux (Android non-root)
# Usage: curl -sL <RAW_URL>/install.sh | bash
#        OR: bash install.sh
# =============================================================================

set -e

# --- Configuration ---
RECODED_VERSION="3.0"

# Detect Termux environment
is_termux() {
    [ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ] || [ "$PREFIX" = "/data/data/com.termux/files/usr" ]
}

if is_termux; then
    IS_TERMUX=true
    INSTALL_DIR="$HOME/.sqlmap-xbibz"
    BIN_DIR="$HOME/.local/bin"
else
    IS_TERMUX=false
    INSTALL_DIR="$HOME/.sqlmap-xbibz"
    BIN_DIR="$HOME/.local/bin"
fi

WRAPPER_SCRIPT="$BIN_DIR/sqlmap"

# --- Colors ---
RED='\033[01;31m'
GREEN='\033[01;32m'
YELLOW='\033[01;33m'
CYAN='\033[01;36m'
WHITE='\033[01;37m'
BOLD='\033[1m'
RESET='\033[0m'

# --- Banner ---
show_banner() {
    echo -e "${RED}"
    echo -e "  +======================================================+"
    echo -e "  |                                                      |"
    echo -e "  |       ${YELLOW}sqlmap Auto-Installer${RED}                        |"
    echo -e "  |       ${CYAN}Recoded By Xbibz Official v${RECODED_VERSION}${RED}             |"
    if [ "$IS_TERMUX" = true ]; then
    echo -e "  |       ${GREEN}[Termux Mode Detected]${RED}                        |"
    fi
    echo -e "  |                                                      |"
    echo -e "  +======================================================+"
    echo -e "${RESET}"
}

# --- Logging helpers ---
info()  { echo -e "${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
error() { echo -e "${RED}[-]${RESET} $1"; }

# --- Detect current shell ---
detect_shell() {
    local shell_name=""

    # Method 1: Check $SHELL environment variable
    if [ -n "$SHELL" ]; then
        shell_name=$(basename "$SHELL")
    fi

    # Method 2: Check the parent process
    if [ -z "$shell_name" ] || [ "$shell_name" = "sh" ]; then
        shell_name=$(ps -p $$ -o comm= 2>/dev/null || echo "")
        if [ "$shell_name" = "sh" ]; then
            shell_name=$(ps -p $PPID -o comm= 2>/dev/null || echo "bash")
        fi
    fi

    # In Termux, default to bash
    if [ -z "$shell_name" ]; then
        shell_name="bash"
    fi

    echo "$shell_name"
}

# --- Detect shell config file ---
detect_rc_file() {
    local shell_name="$1"

    # In Termux, always use .bashrc
    if [ "$IS_TERMUX" = true ]; then
        echo "$HOME/.bashrc"
        return
    fi

    case "$shell_name" in
        zsh)
            echo "$HOME/.zshrc"
            ;;
        bash)
            echo "$HOME/.bashrc"
            ;;
        fish)
            echo "$HOME/.config/fish/config.fish"
            ;;
        *)
            if [ -f "$HOME/.bashrc" ]; then
                echo "$HOME/.bashrc"
            elif [ -f "$HOME/.zshrc" ]; then
                echo "$HOME/.zshrc"
            else
                echo "$HOME/.bashrc"
            fi
            ;;
    esac
}

# --- Check if entry already exists in rc file ---
check_rc_entry() {
    local rc_file="$1"
    grep -q "sqlmap-xbibz" "$rc_file" 2>/dev/null
}

# --- Add PATH and alias to shell rc file ---
setup_shell_rc() {
    local rc_file="$1"
    local shell_name="$2"

    if [ -f "$rc_file" ] && check_rc_entry "$rc_file"; then
        info "Shell config already configured in $rc_file"
        return 0
    fi

    info "Configuring $rc_file for sqlmap command..."

    {
        echo ""
        echo "# =============================================================================="
        echo "# sqlmap-xbibz - Recoded By Xbibz Official"
        echo "# Auto-installed on $(date '+%Y-%m-%d %H:%M:%S')"
        echo "# =============================================================================="

        case "$shell_name" in
            fish)
                echo "if not contains $BIN_DIR \$PATH"
                echo "    set -gx PATH $BIN_DIR \$PATH"
                echo "end"
                echo "alias sqlmap='$WRAPPER_SCRIPT'"
                ;;
            *)
                # Bash / Zsh - use function for robust access
                echo "if [[ \":\$PATH:\" != *\":$BIN_DIR:\"* ]]; then"
                echo "    export PATH=\"$BIN_DIR:\$PATH\""
                echo "fi"
                echo "sqlmap() {"
                echo "    command python3 '$INSTALL_DIR/sqlmap.py' \"\$@\" 2>/dev/null || command python '$INSTALL_DIR/sqlmap.py' \"\$@\""
                echo "}"
                echo "export -f sqlmap 2>/dev/null || true"
                ;;
        esac
    } >> "$rc_file"

    info "Shell config updated: $rc_file"
}

# --- Check Python installation (outputs ONLY the command name to stdout) ---
find_python() {
    local python_cmd=""

    # Priority 1: python3
    if command -v python3 >/dev/null 2>&1; then
        python_cmd="python3"
    # Priority 2: python (check if it's Python 3+)
    elif command -v python >/dev/null 2>&1; then
        local py_ver
        py_ver=$(python -c 'import sys;print(sys.version_info[0])' 2>/dev/null || echo "0")
        if [ "$py_ver" -ge 3 ]; then
            python_cmd="python"
        fi
    fi

    # If still not found, try pkg in Termux
    if [ -z "$python_cmd" ] && [ "$IS_TERMUX" = true ]; then
        info "Installing Python via pkg (Termux)..."
        pkg install -y python 2>/dev/null || apt install -y python 2>/dev/null || true
        if command -v python3 >/dev/null 2>&1; then
            python_cmd="python3"
        elif command -v python >/dev/null 2>&1; then
            python_cmd="python"
        fi
    fi

    # Output only the command name (nothing else to stdout)
    echo "$python_cmd"
}

# --- Verify and report Python ---
check_python() {
    local python_cmd
    python_cmd=$(find_python)

    if [ -z "$python_cmd" ]; then
        error "Python 3 is not installed!"
        echo ""
        if [ "$IS_TERMUX" = true ]; then
            error "Install with: pkg install python"
        else
            error "Install Python 3:"
            error "  Debian/Ubuntu: sudo apt install python3"
            error "  Fedora/RHEL:   sudo dnf install python3"
            error "  Arch:          sudo pacman -S python"
            error "  macOS:         brew install python3"
        fi
        exit 1
    fi

    local py_ver
    py_ver=$($python_cmd --version 2>&1)
    info "Found Python: $py_ver (command: $python_cmd)"

    # Return the command for use by caller
    echo "$python_cmd"
}

# --- Check dependencies ---
check_dependencies() {
    info "Checking dependencies..."

    if command -v pip3 >/dev/null 2>&1; then
        info "Found pip3"
    elif command -v pip >/dev/null 2>&1; then
        info "Found pip"
    else
        if [ "$IS_TERMUX" = true ]; then
            warn "pip not found. Installing via pkg..."
            pkg install -y python-pip 2>/dev/null || true
        else
            warn "pip not found. Some features may not work."
        fi
    fi

    if command -v git >/dev/null 2>&1; then
        info "Found git"
    else
        if [ "$IS_TERMUX" = true ]; then
            warn "git not found. Installing via pkg..."
            pkg install -y git 2>/dev/null || true
        else
            warn "git not found. Updates will be limited."
        fi
    fi

    if command -v curl >/dev/null 2>&1; then
        info "Found curl"
    elif command -v wget >/dev/null 2>&1; then
        info "Found wget (fallback)"
    else
        if [ "$IS_TERMUX" = true ]; then
            warn "curl not found. Installing via pkg..."
            pkg install -y curl 2>/dev/null || true
        else
            warn "Neither curl nor wget found."
        fi
    fi

    # Termux-specific: install build essentials for some Python packages
    if [ "$IS_TERMUX" = true ]; then
        info "Termux: Ensuring essential packages..."
        pkg install -y libxml2 libxslt 2>/dev/null || true
    fi
}

# --- Create the wrapper script ---
create_wrapper() {
    info "Creating sqlmap command wrapper..."

    mkdir -p "$BIN_DIR"

    # Find python - capture ONLY the command name (stderr for logging)
    local python_cmd
    python_cmd=$(find_python)

    if [ -z "$python_cmd" ]; then
        python_cmd="python3"  # fallback
    fi

    info "Wrapper will use: $python_cmd"

    # Write wrapper script - use 'command' to avoid function recursion
    cat > "$WRAPPER_SCRIPT" << WRAPPER_EOF
#!/usr/bin/env bash
# =============================================================================
# sqlmap wrapper - Recoded By Xbibz Official
# This script allows running sqlmap from any terminal by typing "sqlmap"
# Supports: Linux, macOS, Termux (Android non-root)
# =============================================================================

SQLMAP_DIR="$INSTALL_DIR"

# Find Python (try python3 first, then python)
PYTHON_CMD=""
if command -v python3 >/dev/null 2>&1; then
    PYTHON_CMD="python3"
elif command -v python >/dev/null 2>&1; then
    PYTHON_CMD="python"
else
    echo "[-] Error: Python not found!"
    echo "[-] Please install Python 3 first."
    exit 1
fi

# Check if sqlmap.py exists
if [ ! -f "\$SQLMAP_DIR/sqlmap.py" ]; then
    echo "[-] Error: sqlmap.py not found in \$SQLMAP_DIR"
    echo "[-] Please reinstall."
    exit 1
fi

# Run sqlmap with all arguments passed
"\$PYTHON_CMD" "\$SQLMAP_DIR/sqlmap.py" "\$@"
WRAPPER_EOF

    chmod +x "$WRAPPER_SCRIPT" 2>/dev/null || true
    info "Wrapper script created: $WRAPPER_SCRIPT"
}

# --- Add to PATH for current session ---
add_to_current_path() {
    case ":$PATH:" in
        *":$BIN_DIR:"*)
            info "$BIN_DIR already in PATH"
            ;;
        *)
            export PATH="$BIN_DIR:$PATH"
            info "Added $BIN_DIR to PATH for current session"
            ;;
    esac
}

# --- Create uninstall script inside install dir ---
create_uninstaller() {
    mkdir -p "$INSTALL_DIR"

    cat > "$INSTALL_DIR/uninstall.sh" << 'UNINSTALL_EOF'
#!/usr/bin/env bash
# =============================================================================
# sqlmap-xbibz Uninstaller - Recoded By Xbibz Official
# =============================================================================
GREEN='\033[01;32m'; YELLOW='\033[01;33m'; RED='\033[01;31m'; RESET='\033[0m'
info()  { echo -e "${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }

echo -e "${RED}[!] Uninstalling sqlmap-xbibz...${RESET}"

rm -f "$HOME/.local/bin/sqlmap" 2>/dev/null && info "Removed wrapper"
rm -rf "$HOME/.sqlmap-xbibz" 2>/dev/null && info "Removed installation dir"

for rc in "$HOME/.bashrc" "$HOME/.zshrc" "$HOME/.config/fish/config.fish"; do
    if [ -f "$rc" ] && grep -q "sqlmap-xbibz" "$rc" 2>/dev/null; then
        cp "$rc" "${rc}.bak"
        sed -i '/# =.*sqlmap-xbibz/,/# =.*============/d' "$rc"
        sed -i '/^sqlmap()/,/^}/d' "$rc"
        sed -i '/alias sqlmap=/d' "$rc"
        sed -i '/export -f sqlmap/d' "$rc"
        info "Cleaned: $rc"
    fi
done
info "Uninstalled! Restart terminal or: source ~/.bashrc"
UNINSTALL_EOF

    chmod +x "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true
    info "Uninstaller created: $INSTALL_DIR/uninstall.sh"
}

# --- Create update script ---
create_updater() {
    cat > "$INSTALL_DIR/update.sh" << UPDATE_EOF
#!/usr/bin/env bash
# =============================================================================
# sqlmap-xbibz Updater - Recoded By Xbibz Official
# =============================================================================
GREEN='\033[01;32m'; YELLOW='\033[01;33m'; CYAN='\033[01;36m'; RESET='\033[0m'
info()  { echo -e "${GREEN}[+]${RESET} $1"; }
warn()  { echo -e "${YELLOW}[!]${RESET} $1"; }
echo -e "\${CYAN}[*] Updating sqlmap-xbibz...${RESET}"
cd "$INSTALL_DIR" 2>/dev/null || { warn "Installation not found"; exit 1; }
if [ -d ".git" ]; then
    git pull origin master 2>/dev/null && info "Updated!" || warn "Git pull failed"
else
    warn "Not a git repo. Re-run installer for latest version."
fi
UPDATE_EOF

    chmod +x "$INSTALL_DIR/update.sh" 2>/dev/null || true
    info "Updater created: $INSTALL_DIR/update.sh"
}

# --- Main installation ---
main() {
    show_banner

    # Step 1: Check Python
    info "Step 1/6: Checking Python installation..."
    local python_cmd
    python_cmd=$(find_python)
    if [ -n "$python_cmd" ]; then
        info "Found: $($python_cmd --version 2>&1) (command: $python_cmd)"
    else
        if [ "$IS_TERMUX" = true ]; then
            info "Installing Python for Termux..."
            pkg install -y python 2>/dev/null || true
            python_cmd=$(find_python)
        fi
        if [ -z "$python_cmd" ]; then
            error "Python 3 is required but not found!"
            if [ "$IS_TERMUX" = true ]; then
                error "Run: pkg install python"
            else
                error "Run: sudo apt install python3  (or equivalent)"
            fi
            exit 1
        fi
    fi

    # Step 2: Check dependencies
    info "Step 2/6: Checking dependencies..."
    check_dependencies

    # Step 3: Detect shell
    info "Step 3/6: Detecting shell environment..."
    local shell_name
    shell_name=$(detect_shell)
    info "Detected shell: $shell_name"
    if [ "$IS_TERMUX" = true ]; then
        info "Termux environment detected!"
    fi

    local rc_file
    rc_file=$(detect_rc_file "$shell_name")
    info "Shell config file: $rc_file"

    # Report found rc files
    [ -f "$HOME/.bashrc" ] && info "Found: ~/.bashrc"
    [ -f "$HOME/.zshrc" ] && info "Found: ~/.zshrc"

    # Step 4: Install files
    info "Step 4/6: Installing sqlmap-xbibz..."

    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd)" || SCRIPT_DIR="."

    # Remove old installation if exists
    if [ -d "$INSTALL_DIR" ]; then
        warn "Previous installation found. Updating..."
        rm -rf "$INSTALL_DIR"
    fi

    mkdir -p "$INSTALL_DIR"

    if [ -f "$SCRIPT_DIR/sqlmap.py" ]; then
        info "Installing from local directory: $SCRIPT_DIR"
        cp -r "$SCRIPT_DIR/"* "$INSTALL_DIR/" 2>/dev/null || true
        # Also copy hidden files like .git if exists
        cp -r "$SCRIPT_DIR/.git" "$INSTALL_DIR/" 2>/dev/null || true
    else
        info "Downloading sqlmap-xbibz from GitHub..."
        if command -v git >/dev/null 2>&1; then
            info "Cloning via git..."
            git clone --depth 1 "https://github.com/XbibzOfficial777/sqlmap-xbibz.git" "$INSTALL_DIR" 2>/dev/null || \
            git clone --depth 1 "https://github.com/sqlmapproject/sqlmap.git" "$INSTALL_DIR" 2>/dev/null || \
            warn "Git clone failed"
        else
            if command -v curl >/dev/null 2>&1; then
                info "Downloading via curl..."
                curl -sL "https://github.com/sqlmapproject/sqlmap/zipball/master" -o /tmp/sqlmap-xbibz.zip
            elif command -v wget >/dev/null 2>&1; then
                info "Downloading via wget..."
                wget -q "https://github.com/sqlmapproject/sqlmap/zipball/master" -O /tmp/sqlmap-xbibz.zip
            fi
            if [ -f /tmp/sqlmap-xbibz.zip ]; then
                cd /tmp && unzip -qo sqlmap-xbibz.zip 2>/dev/null
                cp -r /tmp/sqlmapproject-sqlmap-*/ "$INSTALL_DIR/" 2>/dev/null || true
                rm -rf /tmp/sqlmapproject-sqlmap-*/ /tmp/sqlmap-xbibz.zip 2>/dev/null
            fi
        fi
    fi

    # Ensure sqlmap.py is executable
    chmod +x "$INSTALL_DIR/sqlmap.py" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/sqlmapapi.py" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/install.sh" 2>/dev/null || true
    chmod +x "$INSTALL_DIR/uninstall.sh" 2>/dev/null || true

    info "Files installed to: $INSTALL_DIR"

    # Step 5: Create wrapper
    info "Step 5/6: Setting up sqlmap command..."
    create_wrapper
    add_to_current_path

    # Step 6: Configure shell rc
    info "Step 6/6: Configuring shell environment..."
    setup_shell_rc "$rc_file" "$shell_name"

    # Dual config: configure the other rc file too if it exists
    if [ "$shell_name" = "zsh" ] && [ -f "$HOME/.bashrc" ]; then
        setup_shell_rc "$HOME/.bashrc" "bash"
    elif [ "$shell_name" = "bash" ] && [ -f "$HOME/.zshrc" ]; then
        setup_shell_rc "$HOME/.zshrc" "zsh"
    fi

    # Create helper scripts
    create_uninstaller
    create_updater

    # --- Success message ---
    echo ""
    echo -e "${GREEN}  +======================================================+${RESET}"
    echo -e "${GREEN}  |${RESET}  ${BOLD}sqlmap installed successfully!${RESET}                       ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${CYAN}Recoded By Xbibz Official v${RECODED_VERSION}${RESET}                   ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}                                                      ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${YELLOW}Install dir:${RESET}  $INSTALL_DIR              ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${YELLOW}Wrapper:${RESET}      $WRAPPER_SCRIPT        ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${YELLOW}Shell rc:${RESET}     $rc_file                ${GREEN}|${RESET}"
    if [ "$IS_TERMUX" = true ]; then
    echo -e "${GREEN}  |${RESET}  ${GREEN}Mode:${RESET}         Termux (Android)         ${GREEN}|${RESET}"
    fi
    echo -e "${GREEN}  |${RESET}                                                      ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${WHITE}Usage:${RESET}   ${BOLD}sqlmap -u \"http://target?id=1\"${RESET}             ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}           ${BOLD}sqlmap --help${RESET}                               ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}           ${BOLD}sqlmap -u URL --auto${RESET} (fully automated)    ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}           ${BOLD}sqlmap -u URL --spider${RESET} (param discovery)  ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}                                                      ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${WHITE}Activate:${RESET} ${BOLD}source $rc_file${RESET}                  ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${WHITE}Uninstall:${RESET} ${BOLD}bash $INSTALL_DIR/uninstall.sh${RESET}        ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}  ${WHITE}Update:${RESET}    ${BOLD}bash $INSTALL_DIR/update.sh${RESET}           ${GREEN}|${RESET}"
    echo -e "${GREEN}  |${RESET}                                                      ${GREEN}|${RESET}"
    echo -e "${GREEN}  +======================================================+${RESET}"
    echo ""
}

main "$@"
