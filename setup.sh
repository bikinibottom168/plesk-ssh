#!/usr/bin/env bash
set -euo pipefail

INSTALL_DIR="/opt/plesk-dashboard"
CONFIG_DIR="/etc/plesk-dashboard"

if [ "$(id -u)" -ne 0 ]; then
  echo "ต้องรันด้วย root หรือ sudo" >&2
  exit 1
fi

SOURCE_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "==> สร้าง directories"
install -d -m 750 "$INSTALL_DIR" "$CONFIG_DIR"

echo "==> ติดตั้ง Python deps"
python3 -m pip install --upgrade -r "$SOURCE_DIR/requirements.txt"

echo "==> สร้าง self-signed cert (ถ้ายังไม่มี)"
if [ ! -f "$CONFIG_DIR/cert.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -nodes -days 3650 \
    -keyout "$CONFIG_DIR/key.pem" \
    -out "$CONFIG_DIR/cert.pem" \
    -subj "/CN=plesk-dashboard"
  chmod 640 "$CONFIG_DIR/cert.pem" "$CONFIG_DIR/key.pem"
fi

echo "==> สร้าง config (ถ้ายังไม่มี)"
if [ ! -f "$CONFIG_DIR/config.json" ]; then
  cp "$SOURCE_DIR/config.example.json" "$CONFIG_DIR/config.json"
  SECRET=$(openssl rand -hex 32)
  sed -i "s|CHANGE_ME_TO_RANDOM_64_HEX_CHARS|$SECRET|" "$CONFIG_DIR/config.json"
  echo
  echo "*** สร้าง bcrypt hash ของรหัส admin ก่อน:"
  echo "***   python3 $INSTALL_DIR/server.py --hash-password 'YOUR_PASSWORD'"
  echo "*** แล้วเอาไปใส่ใน $CONFIG_DIR/config.json ที่ key users.admin"
  echo
fi

echo "==> Copy ไฟล์ไป $INSTALL_DIR"
rsync -a --delete \
  --exclude '.git' --exclude '__pycache__' --exclude 'config.json' \
  "$SOURCE_DIR/" "$INSTALL_DIR/"

echo "==> ติดตั้ง systemd unit"
cp "$SOURCE_DIR/plesk-dashboard.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable plesk-dashboard

echo "==> เปิด firewall ports"
if command -v plesk >/dev/null 2>&1; then
  plesk bin firewall --add-rule -name plesk-dashboard \
    -ports "9080:tcp,9443:tcp" -direction input -action allow 2>/dev/null || true
fi

cat <<EOF

ติดตั้งเสร็จ
  1) ตั้งรหัส:    python3 $INSTALL_DIR/server.py --hash-password 'PASSWORD'
                   เอา hash ไปใส่ใน $CONFIG_DIR/config.json (users.admin)
  2) สตาร์ท:      systemctl start plesk-dashboard
  3) ดู log:      journalctl -u plesk-dashboard -f
  4) เปิดเว็บ:    https://<server-ip>:9443

EOF
