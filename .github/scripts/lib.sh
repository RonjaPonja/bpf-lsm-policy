#!/bin/bash

set -a
[ -f /etc/environment ] && source /etc/environment
set +a

export FORCE_COLOR=1
export TERM=xterm-256color
export CLICOLOR_FORCE=1

RED=$'\033[0;31m'
GREEN=$'\033[0;32m'
YELLOW=$'\033[0;33m'
BLUE=$'\033[0;34m'
CYAN=$'\033[0;36m'
NC=$'\033[0m' # No Color

export LOG_LEVEL="${LOG_LEVEL:-2}"

log_debug()   { [ "$LOG_LEVEL" -ge 3 ] && printf "%s[DEBUG] %s%s\n" "$CYAN" "$1" "$NC" || true; }
log_info()    { [ "$LOG_LEVEL" -ge 2 ] && printf "%s[INFO] %s%s\n" "$BLUE" "$1" "$NC" || true; }
log_success() { [ "$LOG_LEVEL" -ge 2 ] && printf "%s[SUCCESS] %s%s\n" "$GREEN" "$1" "$NC" || true; }
log_warn()    { [ "$LOG_LEVEL" -ge 1 ] && printf "%s[WARN] %s%s\n" "$YELLOW" "$1" "$NC" || true; }
log_error()   { [ "$LOG_LEVEL" -ge 0 ] && printf "%s[ERROR] %s%s\n" "$RED" "$1" "$NC" || true; }
