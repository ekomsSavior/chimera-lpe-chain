#!/bin/bash
# build.sh — Build CHIMERA chain + all exploits
set -e

echo "[*] CHIMERA — Building chain + all exploits"
echo ""

cd "$(dirname "$0")"

# Build chain
echo "[*] Building chain.c..."
gcc -O2 -Wall -Werror -o chain chain.c -lpthread
echo "[+] chain built"

# Build exploits
mkdir -p exploits
cd exploits
echo "[*] Building exploits..."

build_one() {
    local src="$1"
    local extra="$2"
    local out="${src%.c}"

    if [ ! -f "$src" ]; then
        echo "[-] $src not found, skipping"
        return
    fi

    if gcc -O2 -Wall -Werror -o "$out" "$src" $extra 2>/dev/null; then
        echo "[+] $out built"
    else
        echo "[!] $out build failed (missing deps?)"
    fi
}

build_one "cve-2026-53359.c" "-lpthread"
build_one "cve-2026-53341.c" "-lpthread"
build_one "cve-2026-53362.c" "-lpthread"
build_one "cve-2026-53389.c" "-lpthread"
build_one "cve-2026-53374.c" "-ldrm"
build_one "cve-2026-53354.c" "-lpthread"

echo ""
echo "[*] Done. Binaries:"
ls -la cve-2026-* 2>/dev/null | awk '{print "  " $NF "  (" $5 " bytes)"}'
