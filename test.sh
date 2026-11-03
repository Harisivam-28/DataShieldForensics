#!/usr/bin/env bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

if [ -x "/opt/homebrew/opt/openjdk@17/bin/java" ]; then
    JAVA_BIN="/opt/homebrew/opt/openjdk@17/bin/java"
elif command -v java >/dev/null 2>&1 && java -version >/dev/null 2>&1; then
    JAVA_BIN="java"
else
    echo "[!] Error: No Java runtime (java) found."
    exit 1
fi

if [ ! -f "target/datashield-forensics.jar" ]; then
    echo "[*] JAR not found, building first..."
    ./build.sh
fi

exec $JAVA_BIN -jar target/datashield-forensics.jar --test
