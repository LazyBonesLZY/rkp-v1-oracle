#!/system/bin/sh
# ============================================================================
# RKP V1 Oracle installer
# Deploys the on-device keybox provisioner. Copy this folder anywhere on the
# device and run as root:  sh install.sh
# ============================================================================
set -eu

SRC_DIR="$(cd "$(dirname "$0")" && pwd)"
DEST="/data/local/tmp/rkp-oracle"

[ "$(id -u)" = "0" ] || { echo "ERROR: run as root (su)"; exit 1; }
echo "[1/3] checking environment..."

# --- stage this device's own AIDL apk (version-matched proxy classes) ---
APK=""
for d in /apex/com.android.rkpd/priv-app/*/; do
    [ -f "$d/rkpdapp.apk" ] && APK="$d/rkpdapp.apk" && break
done
[ -n "$APK" ] || APK="$(find /apex/com.android.rkpd -name 'rkpdapp.apk' 2>/dev/null | head -1)"
[ -n "$APK" ] || { echo "ERROR: rkpdapp.apk not found in /apex"; exit 1; }

service check android.hardware.security.keymint.IRemotelyProvisionedComponent/default >/dev/null 2>&1 \
    || ls /dev/smcinvoke >/dev/null 2>&1 \
    || { echo "ERROR: IRemotelyProvisionedComponent HAL unavailable"; exit 1; }

mkdir -p "$DEST"
cp "$APK" "$DEST/rkpdapp.apk" && chmod 644 "$DEST/rkpdapp.apk"

echo "[2/3] deploying jar..."
cp "$SRC_DIR/rkporacle.jar" "$DEST/rkporacle.jar"
chmod 644 "$DEST/rkporacle.jar"

echo "[3/3] writing run script..."
cat > "$DEST/provision.sh" << 'RUNEOF'
#!/system/bin/sh
# Provision a fresh Google-signed keybox entirely on-device.
# usage: sh provision.sh [output-dir]
set -u
DEST="/data/local/tmp/rkp-oracle"
OUT="${1:-$DEST/$(date +%Y%m%d-%H%M%S)}"

[ "$(id -u)" = "0" ] || { echo "ERROR: root required"; exit 1; }
[ -f "$DEST/rkporacle.jar" ] || { echo "ERROR: rkporacle.jar missing (rerun install.sh)"; exit 1; }
[ -f "$DEST/rkpdapp.apk" ] || { echo "ERROR: rkpdapp.apk missing (rerun install.sh)"; exit 1; }

mkdir -p "$OUT"
echo "[*] provisioning to: $OUT"
echo "[*] two Google round-trips; can take up to ~2 min on slow networks"

LOG=$(CLASSPATH="$DEST/rkporacle.jar:$DEST/rkpdapp.apk" \
      timeout 150 app_process /system/bin rkp.RkpOracle "$OUT" 2>&1) || true
echo "$LOG"

if [ ! -f "$OUT/keybox.xml" ]; then
    echo "$LOG" > "$OUT/error.log"
    echo "FAILED — see $OUT/error.log"
    exit 1
fi

echo "=== keybox.xml ready ($(grep -c 'BEGIN CERTIFICATE' "$OUT/keybox.xml") certs) ==="
echo "    $OUT/keybox.xml        (install into your keystore module of choice)"
echo "    $OUT/attest_key_priv.pem"
echo "    $OUT/cert_chain.der"
RUNEOF
chmod 755 "$DEST/provision.sh"

echo ""
echo "=== INSTALL COMPLETE ==="
echo "usage:  sh $DEST/provision.sh [outdir]   # mint a fresh keybox"
