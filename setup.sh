#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/plesk-dashboard"
CONFIG_DIR="/etc/plesk-dashboard"
VENV_DIR="$INSTALL_DIR/venv"

if [ "$(id -u)" -ne 0 ]; then
  echo "ต้องรันด้วย root หรือ sudo" >&2
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

# ---------- check + install OS packages ----------
echo "==> ตรวจสอบเครื่องมือที่จำเป็น"

declare -a missing=()
declare -a missing_pkgs=()

check() {
  # check <command-or-python-mod> <kind: cmd|pymod> <pkg-name>
  local target="$1" kind="$2" pkg="$3"
  local present=0
  case "$kind" in
    cmd)   command -v "$target" >/dev/null 2>&1 && present=1 ;;
    pymod) python3 -c "import $target" >/dev/null 2>&1 && present=1 ;;
    file)  [ -e "$target" ] && present=1 ;;
  esac
  if [ "$present" -eq 1 ]; then
    printf "    \xe2\x9c\x93 %s\n" "$target"
  else
    printf "    \xe2\x9c\x97 %s -> จะติดตั้ง %s\n" "$target" "$pkg"
    missing+=("$target")
    missing_pkgs+=("$pkg")
  fi
}

# Detect package manager
PKG_MGR=""
if   command -v apt-get >/dev/null 2>&1; then PKG_MGR=apt
elif command -v dnf     >/dev/null 2>&1; then PKG_MGR=dnf
elif command -v yum     >/dev/null 2>&1; then PKG_MGR=yum
fi

if [ -z "$PKG_MGR" ]; then
  echo "    ไม่รู้จัก package manager — ตรวจสอบเองให้ครบ" >&2
fi

# pkg names by distro
if [ "$PKG_MGR" = "apt" ]; then
  PKG_MYSQLDUMP=mariadb-client
else
  PKG_MYSQLDUMP=mariadb
fi

# venv must be tested by actually creating one — `import venv` ผ่านได้
# แม้ ensurepip data ขาด (เคส python3.X-venv ไม่ติดตั้งบน Debian)
test_venv_works() {
  local tmp
  tmp=$(mktemp -d) || return 1
  python3 -m venv "$tmp/t" >/dev/null 2>&1
  local rc=$?
  rm -rf "$tmp"
  return $rc
}

if test_venv_works; then
  echo "    ✓ python venv"
else
  PY_VER=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
  echo "    ✗ python venv -> จะติดตั้ง python${PY_VER}-venv + python3-pip"
  case "$PKG_MGR" in
    apt)
      apt-get update
      apt-get install -y "python${PY_VER}-venv" python3-venv python3-pip 2>/dev/null \
        || apt-get install -y python3-venv python3-pip
      ;;
    dnf) dnf install -y python3-pip ;;
    yum) yum install -y python3-pip ;;
    *)
      echo "    โปรดติดตั้ง venv + pip เอง" >&2
      exit 1
      ;;
  esac

  if ! test_venv_works; then
    echo "ERROR: venv ใช้งานไม่ได้แม้ติดตั้งแล้ว — ลองติดตั้ง python${PY_VER}-venv เอง" >&2
    exit 1
  fi
  echo "    ✓ python venv (หลังติดตั้ง)"
fi

check openssl   cmd   openssl
check rsync     cmd   rsync
check mysqldump cmd   "$PKG_MYSQLDUMP"
check tar       cmd   tar
check gzip      cmd   gzip
check /etc/ssl/certs/ca-certificates.crt file ca-certificates

if [ ${#missing_pkgs[@]} -gt 0 ] && [ -n "$PKG_MGR" ]; then
  # de-dup
  uniq_pkgs=$(printf "%s\n" "${missing_pkgs[@]}" | awk '!seen[$0]++' | tr '\n' ' ')
  echo "==> ติดตั้ง: $uniq_pkgs"
  case "$PKG_MGR" in
    apt) apt-get update && apt-get install -y $uniq_pkgs ;;
    dnf) dnf install -y $uniq_pkgs ;;
    yum) yum install -y $uniq_pkgs ;;
  esac
fi

# Plesk presence (required, but don't install — it's the host platform)
if ! command -v plesk >/dev/null 2>&1; then
  echo "    !! ไม่พบคำสั่ง 'plesk' — UI ส่วนใหญ่จะใช้งานไม่ได้บนเครื่องนี้" >&2
else
  echo "    ✓ plesk"
fi

# ---------- venv + Python deps ----------
echo "==> สร้าง directories"
install -d -m 750 "$INSTALL_DIR" "$CONFIG_DIR"

echo "==> สร้าง virtualenv ที่ $VENV_DIR"
# ลบ venv ที่เสีย (ขาด python หรือ pip) จาก run ก่อนหน้าที่ล้มกลางคัน
if [ -d "$VENV_DIR" ]; then
  if [ ! -x "$VENV_DIR/bin/python" ] || [ ! -x "$VENV_DIR/bin/pip" ]; then
    echo "    พบ venv เดิมเสีย (ขาด python/pip) — ลบทิ้ง"
    rm -rf "$VENV_DIR"
  fi
fi
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi
# ตรวจหลังสร้างว่า pip ใช้งานได้จริง
if [ ! -x "$VENV_DIR/bin/pip" ]; then
  echo "ERROR: venv สร้างแล้วแต่ไม่มี pip — โปรดติดตั้ง python$(python3 -c 'import sys;print(f\"{sys.version_info.major}.{sys.version_info.minor}\")')-venv ให้ครบ" >&2
  exit 1
fi

echo "==> ติดตั้ง Python deps ใน venv"
"$VENV_DIR/bin/pip" install --upgrade pip
"$VENV_DIR/bin/pip" install --upgrade -r "$SOURCE_DIR/requirements.txt"

# ---------- self-signed cert ----------
echo "==> สร้าง self-signed cert (ถ้ายังไม่มี)"
if [ ! -f "$CONFIG_DIR/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CONFIG_DIR/key.pem" \
    -out "$CONFIG_DIR/cert.pem" \
    -subj "/CN=plesk-dashboard"
  chmod 640 "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"
fi

# ---------- config ----------
echo "==> สร้าง config (ถ้ายังไม่มี)"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
  cp "$SOURCE_DIR/config.example.json" "$CONFIG_DIR/config.json"
  SECRET=$(openssl rand -hex 32)
  sed -i "s|CHANGE_ME_TO_RANDOM_64_HEX_CHARS|$SECRET|" "$CONFIG_DIR/config.json"
fi

# ---------- admin password ----------
echo "==> ตั้งรหัสผ่าน admin"
ADMIN_HASH=$("$VENV_DIR/bin/python" -c "import bcrypt; print(bcrypt.hashpw(b'iceza0251', bcrypt.gensalt()).decode())")
"$VENV_DIR/bin/python" - <<PYEOF
import json
cfg_path = "$CONFIG_DIR/config.json"
with open(cfg_path) as f:
    cfg = json.load(f)
cfg["users"] = {"admin": "$ADMIN_HASH"}
with open(cfg_path, "w") as f:
    json.dump(cfg, f, indent=2)
print("    ✓ admin / iceza0251")
PYEOF

# ---------- copy files ----------
echo "==> Copy ไฟล์ไป $INSTALL_DIR"
if command -v rsync >/dev/null 2>&1; then
  rsync -a \
    --exclude '.git' --exclude '__pycache__' \
    --exclude 'config.json' --exclude 'venv' \
    "$SOURCE_DIR/" "$INSTALL_DIR/"
else
  for item in admin.py server.py requirements.txt config.example.json \
              plesk-dashboard.service templates README-dashboard.md; do
    if [ -e "$SOURCE_DIR/$item" ]; then
      cp -a "$SOURCE_DIR/$item" "$INSTALL_DIR/"
    fi
  done
fi

# ---------- systemd ----------
# Verify templates were copied
if [ ! -d "$INSTALL_DIR/templates" ]; then
  echo "ERROR: ไม่พบ $INSTALL_DIR/templates หลัง copy — UI จะใช้งานไม่ได้" >&2
  exit 1
fi

echo "==> ติดตั้ง systemd unit"
cp "$SOURCE_DIR/plesk-dashboard.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable plesk-dashboard

# Restart ถ้ารันอยู่ (เพื่อให้โหลด config / โค้ดใหม่)
if systemctl is-active --quiet plesk-dashboard; then
  echo "==> Restart service"
  systemctl restart plesk-dashboard
fi

# ---------- firewall ----------
echo "==> เปิด firewall ports"
if command -v plesk >/dev/null 2>&1; then
  plesk bin firewall --add-rule -name plesk-dashboard \
    -ports "9080:tcp,9443:tcp" -direction input -action allow 2>/dev/null || true
fi

# ---------- done ----------
cat <<EOF

ติดตั้งเสร็จเรียบร้อย

  Login:        admin / iceza0251

  สตาร์ท:       systemctl start plesk-dashboard
  ตรวจสอบ:      systemctl status plesk-dashboard
  ดู log:       journalctl -u plesk-dashboard -f
  เปิดเว็บ:     https://<server-ip>:9443

EOF
