# Plesk Dashboard

UI dashboard ทางเลือกสำหรับจัดการโดเมน/ไฟล์/backup บน Plesk รันอยู่บนพอร์ต **9080 (HTTP)** หรือ **9443 (HTTPS)** แยกจาก Plesk panel เดิม (8443)

## ติดตั้งครั้งแรก

```bash
# 1) คัดลอกไฟล์ไปเซิร์ฟเวอร์ Plesk
scp -r plesk-ssh/ root@server:/root/

# 2) รันสคริปต์ติดตั้ง
cd /root/plesk-ssh
chmod +x setup.sh
sudo ./setup.sh
```

สคริปต์จะ:
- ติดตั้ง Python deps (FastAPI, uvicorn, bcrypt, ฯลฯ)
- สร้าง self-signed cert ที่ `/etc/plesk-dashboard/`
- คัดลอกไฟล์ไป `/opt/plesk-dashboard/`
- ติดตั้ง systemd unit `plesk-dashboard.service`
- เปิด firewall port 9080 / 9443

## ตั้งรหัสผ่าน admin

```bash
# สร้าง bcrypt hash
python3 /opt/plesk-dashboard/server.py --hash-password 'YOUR_PASSWORD'
```

เอา hash ที่ได้ไปใส่ใน `/etc/plesk-dashboard/config.json`:

```json
{
  ...
  "users": {
    "admin": "$2b$12$..."
  }
}
```

แล้วสตาร์ท:

```bash
systemctl start plesk-dashboard
systemctl status plesk-dashboard
journalctl -u plesk-dashboard -f
```

เปิดเว็บ: `https://<server-ip>:9443`

## ไฟล์ config

`/etc/plesk-dashboard/config.json`:

| key | คำอธิบาย |
|---|---|
| `host` | IP ที่ bind (`0.0.0.0` รับทุก interface) |
| `http_port` / `https_port` | พอร์ต |
| `ssl_cert` / `ssl_key` | path ของ certificate (ถ้าไม่มี รัน HTTP) |
| `session_secret` | secret ของ session cookie (random hex 64 ตัว) |
| `vhosts_root` | root ของ Plesk vhosts (ปกติ `/var/www/vhosts`) |
| `backup_dir` | โฟลเดอร์เก็บ backup |
| `plesk_panel_url` | URL ของ Plesk panel (สำหรับ link ไป phpMyAdmin) |
| `users` | dict `username` → bcrypt hash |

## ฟีเจอร์ปัจจุบัน

- เข้าสู่ระบบด้วย username/password (bcrypt + session cookie)
- ลิสต์โดเมนทั้งหมด พร้อมหน้า detail
- เปลี่ยนชื่อโดเมน
- เปลี่ยน PHP version
- ดูรหัสผ่าน FTP (ถอดรหัส AES อัตโนมัติถ้ามี encrypt3)
- Backup: subscription / files (tar.gz) / database (mysqldump)
- File manager: เปิดโฟลเดอร์ ดู/แก้/อัปโหลด/ดาวน์โหลด/ลบไฟล์
- รายการฐานข้อมูล (ลิงก์ออกไป phpMyAdmin ของ Plesk)

## ความปลอดภัย

UI นี้รันด้วย root และเรียก `plesk bin` ได้ตรง — **ห้ามเปิดสู่อินเทอร์เน็ตโดยไม่มี HTTPS**

แนะนำเพิ่มเติม:
- ใช้ Let's Encrypt cert ของจริง (แทน self-signed) โดยแก้ `ssl_cert`/`ssl_key` ใน config
- จำกัด IP ที่เข้าถึง 9443 ผ่าน iptables / Plesk firewall
- ตั้ง `session_secret` เป็น random ที่ยาว ๆ (sha256 ของอะไรก็ได้)
- เปลี่ยน password เป็นประจำ

## โครงสร้าง

```
/opt/plesk-dashboard/
├── admin.py              # CLI tool (เดิม)
├── server.py             # FastAPI app
├── templates/            # Jinja2 + Tailwind + HTMX
└── requirements.txt

/etc/plesk-dashboard/
├── config.json           # ค่า config + user hash
├── cert.pem
└── key.pem

/etc/systemd/system/
└── plesk-dashboard.service
```

## Roadmap

ฟีเจอร์ที่ยังไม่ได้ทำ (จะ iterate ต่อ):

- Streaming output ตอน backup (ตอนนี้รอจบก่อนถึงแสดงผล)
- File manager: rename, mkdir, sync editor (CodeMirror)
- Job queue สำหรับงาน long-running
- Audit log
- 2FA
- IP allowlist ใน config (ตอนนี้พึ่ง firewall)
