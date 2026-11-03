#!/usr/bin/env bash
set -e

# DataShield Forensics - Build Script
echo "=========================================================="
echo " Building DataShield Forensics Java 17 Project"
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Locate Java compiler
if [ -x "/opt/homebrew/opt/openjdk@17/bin/javac" ]; then
    JAVAC_BIN="/opt/homebrew/opt/openjdk@17/bin/javac"
    JAR_BIN="/opt/homebrew/opt/openjdk@17/bin/jar"
elif command -v javac >/dev/null 2>&1 && javac -version >/dev/null 2>&1; then
    JAVAC_BIN="javac"
    JAR_BIN="jar"
else
    echo "[!] Error: No Java compiler (javac) found in PATH or Homebrew OpenJDK 17."
    exit 1
fi

mkdir -p target/classes

echo "[*] Compiling Java source files..."
$JAVAC_BIN -d target/classes $(find src/main/java src/test/java -name "*.java")

echo "[*] Packaging executable JAR target/datashield-forensics.jar..."
$JAR_BIN cfe target/datashield-forensics.jar org.datashield.DataShieldApplication -C target/classes .

echo "=========================================================="
echo " [✓] Build Complete: target/datashield-forensics.jar"
echo " Run with: ./run.sh or java -jar target/datashield-forensics.jar"
echo " Test with: ./test.sh"
echo "=========================================================="
