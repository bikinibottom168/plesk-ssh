#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import shlex
import subprocess
import sys
from datetime import datetime
from pathlib import Path


DEFAULT_VHOSTS_ROOT = "/var/www/vhosts"


def eprint(*args, **kwargs):
    print(*args, file=sys.stderr, **kwargs)


def now_ts():
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def require_root():
    if hasattr(os, "geteuid") and os.geteuid() != 0:
        eprint("ERROR: กรุณารันด้วย root หรือ sudo")
        sys.exit(1)


def run_cmd(cmd, check=True, capture_output=False, env=None):
    if isinstance(cmd, str):
        cmd = shlex.split(cmd)

    proc = subprocess.run(
        cmd,
        text=True,
        capture_output=capture_output,
        env=env,
    )

    if check and proc.returncode != 0:
        if capture_output:
            eprint(proc.stderr.strip() or proc.stdout.strip())
        raise SystemExit(proc.returncode)

    return proc


def run_shell(command, check=True):
    proc = subprocess.run(command, shell=True)
    if check and proc.returncode != 0:
        raise SystemExit(proc.returncode)
    return proc


def safe_filename(name: str) -> str:
    return "".join(c if c.isalnum() or c in ("-", "_", ".") else "_" for c in name)


def ensure_dir(path: str):
    Path(path).mkdir(parents=True, exist_ok=True)


def build_plesk_bin():
    return ["plesk", "bin"]


def cmd_list(args):
    cmd = build_plesk_bin() + ["site", "--list"]
    run_cmd(cmd, check=True, capture_output=False)


def cmd_rename_domain(args):
    old_domain = args.old_domain
    new_domain = args.new_domain

    # ใช้ subscription สำหรับ rename domain ของ subscription
    cmd = build_plesk_bin() + ["subscription", "-u", old_domain, "-new_name", new_domain]

    if args.dry_run:
        print("DRY RUN:", shlex.join(cmd))
        return

    run_cmd(cmd, check=True)
    print(f"OK: renamed {old_domain} -> {new_domain}")


def cmd_backup_subscription(args):
    domain = args.domain
    output = args.output
    ensure_dir(os.path.dirname(output) or ".")

    cmd = build_plesk_bin() + ["pleskbackup", "--domains-name", domain, "-output-file", output]

    if args.incremental:
        cmd.append("-incremental")

    if args.keep_local_backup:
        cmd.append("-keep-local-backup")

    if args.verbose:
        cmd.extend(["-v"] * min(args.verbose, 5))

    if args.dry_run:
        print("DRY RUN:", shlex.join(cmd))
        return

    run_cmd(cmd, check=True)
    print(f"OK: subscription backup created: {output}")


def cmd_restore_subscription(args):
    backup_file = args.backup_file
    domain = args.domain

    cmd = build_plesk_bin() + ["pleskrestore", "--restore", backup_file]

    if args.only == "all":
        pass
    elif args.only == "databases":
        cmd += ["-only-databases"]
        if domain:
            cmd += ["-domain-name", domain]
    elif args.only == "web":
        # restore all web content under subscription/domain
        if not domain:
            eprint("ERROR: --domain ต้องระบุเมื่อใช้ --only web")
            sys.exit(1)
        cmd += ["-only-web-content", "list:/", "-domain-name", domain]
    elif args.only == "dns":
        if not domain:
            eprint("ERROR: --domain ต้องระบุเมื่อใช้ --only dns")
            sys.exit(1)
        cmd += ["-only-dns-zones", "list:" + domain, "-domain-name", domain]

    if args.configuration_only:
        cmd.append("-configuration-only")

    if args.content_only:
        cmd.append("-content-only")

    if args.verbose:
        cmd.append("-verbose")

    if args.dry_run:
        print("DRY RUN:", shlex.join(cmd))
        return

    run_cmd(cmd, check=True)
    print(f"OK: restore finished from {backup_file}")


def cmd_backup_site_files(args):
    domain = args.domain
    vhosts_root = args.vhosts_root
    source = args.source or f"{vhosts_root}/{domain}/httpdocs"
    ensure_dir(args.output_dir)

    outfile = os.path.join(
        args.output_dir,
        f"{safe_filename(domain)}_files_{now_ts()}.tar.gz"
    )

    exclude_args = []
    for item in args.exclude:
        exclude_args.extend(["--exclude", item])

    tar_cmd = ["tar", "-czf", outfile] + exclude_args + ["-C", source, "."]

    if args.dry_run:
        print("DRY RUN:", shlex.join(tar_cmd))
        return

    if not os.path.isdir(source):
        eprint(f"ERROR: ไม่พบ source path: {source}")
        sys.exit(1)

    run_cmd(tar_cmd, check=True)
    print(f"OK: files backup created: {outfile}")


def cmd_backup_db(args):
    ensure_dir(args.output_dir)
    db_name = args.db_name
    outfile = os.path.join(
        args.output_dir,
        f"{safe_filename(db_name)}_db_{now_ts()}.sql"
    )

    if args.gzip:
        outfile += ".gz"

    if args.engine not in ("mysql", "mariadb"):
        eprint("ERROR: ตอนนี้รองรับเฉพาะ mysql/mariadb")
        sys.exit(1)

    cmd = [
        "mysqldump",
        f"--host={args.host}",
        f"--port={args.port}",
        f"--user={args.db_user}",
        "--single-transaction",
        "--quick",
        "--routines",
        "--triggers",
        "--default-character-set=utf8mb4",
        db_name,
    ]

    env = os.environ.copy()
    env["MYSQL_PWD"] = args.db_pass

    if args.dry_run:
        shown = cmd.copy()
        print("DRY RUN:", shlex.join(shown), ">", outfile)
        return

    if args.gzip:
        shell_cmd = f"{shlex.join(cmd)} | gzip > {shlex.quote(outfile)}"
        run_shell(shell_cmd, check=True)
    else:
        with open(outfile, "w") as f:
            proc = subprocess.run(cmd, text=True, stdout=f, env=env)
            if proc.returncode != 0:
                raise SystemExit(proc.returncode)

    print(f"OK: database backup created: {outfile}")


def cmd_list_scheduled_backups(args):
    cmd = build_plesk_bin() + ["scheduled-backup", "--list", "-all"]
    run_cmd(cmd, check=True, capture_output=False)


def cmd_configure_scheduled_backup(args):
    cmd = build_plesk_bin() + [
        "scheduled-backup",
        "--configure",
        args.frequency,
        "-storage",
        args.storage,
        "-backup-time",
        args.time,
        "-incremental",
        str(args.incremental).lower(),
        "-exclude-mail",
        str(args.exclude_mail).lower(),
        "-exclude-user-files",
        str(args.exclude_user_files).lower(),
        "-exclude-databases",
        str(args.exclude_databases).lower(),
    ]

    if args.frequency == "weekly":
        cmd += ["-backup-weekday", args.weekday]

    if args.frequency == "monthly":
        cmd += ["-backup-day", args.monthday]

    if args.keep_in_server_storage is not None:
        cmd += ["-keep-in-server-storage", str(args.keep_in_server_storage).lower()]

    if args.dry_run:
        print("DRY RUN:", shlex.join(cmd))
        return

    run_cmd(cmd, check=True)
    print("OK: scheduled backup configured")


def cmd_plesk_help(args):
    utility = args.utility
    cmd = build_plesk_bin() + [utility, "--help"]
    run_cmd(cmd, check=True, capture_output=False)


def build_parser():
    parser = argparse.ArgumentParser(
        prog="admin.py",
        description="Plesk SSH admin helper: list domains, rename domain, backup site/files/database, restore backup, scheduled backup",
        epilog=(
            "Examples:\n"
            "  admin.py list\n"
            "  admin.py rename-domain example.com newexample.com\n"
            "  admin.py backup-subscription example.com -o /root/backups/example.com.tar\n"
            "  admin.py backup-site-files example.com -O /root/backups\n"
            "  admin.py backup-db mydb -u dbuser -p 'secret' -O /root/backups\n"
            "  admin.py restore-subscription /root/backups/example.com.tar --only databases --domain example.com\n"
            "  admin.py scheduled-backup-list\n"
            "  admin.py scheduled-backup-config --frequency daily --time 03:30\n"
            "  admin.py plesk-help site\n"
            "  admin.py plesk-help subscription\n"
            "  admin.py plesk-help pleskbackup\n"
        ),
        formatter_class=argparse.RawTextHelpFormatter,
    )

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("list", help="เช็คลิสต์โดเมนทั้งหมดใน Plesk")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("rename-domain", help="เปลี่ยนชื่อโดเมนใน Plesk")
    p.add_argument("old_domain", help="โดเมนเดิม เช่น example.com")
    p.add_argument("new_domain", help="โดเมนใหม่ เช่น newexample.com")
    p.add_argument("--dry-run", action="store_true", help="แสดงคำสั่งโดยไม่รันจริง")
    p.set_defaults(func=cmd_rename_domain)

    p = sub.add_parser("backup-subscription", help="สำรอง subscription/domain ผ่าน Plesk backup")
    p.add_argument("domain", help="ชื่อโดเมน/subscription")
    p.add_argument("-o", "--output", required=True, help="ไฟล์ปลายทาง เช่น /root/backups/example.com.tar")
    p.add_argument("--incremental", action="store_true", help="ทำ incremental backup")
    p.add_argument("--keep-local-backup", action="store_true", help="เก็บ local backup ไว้ใน Plesk storage ด้วย")
    p.add_argument("-v", "--verbose", action="count", default=0, help="เพิ่ม verbosity")
    p.add_argument("--dry-run", action="store_true", help="แสดงคำสั่งโดยไม่รันจริง")
    p.set_defaults(func=cmd_backup_subscription)

    p = sub.add_parser("restore-subscription", help="กู้คืน backup ผ่าน Plesk restore")
    p.add_argument("backup_file", help="ไฟล์ backup")
    p.add_argument("--only", choices=["all", "databases", "web", "dns"], default="all",
                   help="เลือกว่าจะ restore อะไร")
    p.add_argument("--domain", help="ชื่อโดเมน ใช้กับบางโหมด เช่น databases/web/dns")
    p.add_argument("--configuration-only", action="store_true", help="restore เฉพาะ config")
    p.add_argument("--content-only", action="store_true", help="restore เฉพาะ content")
    p.add_argument("--verbose", action="store_true", help="เปิด verbose mode")
    p.add_argument("--dry-run", action="store_true", help="แสดงคำสั่งโดยไม่รันจริง")
    p.set_defaults(func=cmd_restore_subscription)

    p = sub.add_parser("backup-site-files", help="backup เฉพาะไฟล์เว็บ เช่น httpdocs เป็น tar.gz")
    p.add_argument("domain", help="ชื่อโดเมน")
    p.add_argument("-O", "--output-dir", default="/root/backups", help="โฟลเดอร์เก็บ backup")
    p.add_argument("--vhosts-root", default=DEFAULT_VHOSTS_ROOT, help="ค่าเริ่มต้น /var/www/vhosts")
    p.add_argument("--source", help="ระบุ source path เอง ถ้าไม่ได้ใช้ httpdocs ปกติ")
    p.add_argument("--exclude", action="append", default=[], help="exclude path เช่น --exclude cache --exclude node_modules")
    p.add_argument("--dry-run", action="store_true", help="แสดงคำสั่งโดยไม่รันจริง")
    p.set_defaults(func=cmd_backup_site_files)

    p = sub.add_parser("backup-db", help="backup ฐานข้อมูลด้วย mysqldump")
    p.add_argument("db_name", help="ชื่อฐานข้อมูล")
    p.add_argument("-u", "--db-user", required=True, help="ชื่อผู้ใช้ฐานข้อมูล")
    p.add_argument("-p", "--db-pass", required=True, help="รหัสผ่านฐานข้อมูล")
    p.add_argument("--host", default="127.0.0.1", help="DB host")
    p.add_argument("--port", default="3306", help="DB port")
    p.add_argument("--engine", default="mysql", choices=["mysql", "mariadb"], help="ชนิดฐานข้อมูล")
    p.add_argument("-O", "--output-dir", default="/root/backups", help="โฟลเดอร์เก็บ backup")
    p.add_argument("--gzip", action="store_true", help="บีบอัดเป็น .gz")
    p.add_argument("--dry-run", action="store_true", help="แสดงคำสั่งโดยไม่รันจริง")
    p.set_defaults(func=cmd_backup_db)

    p = sub.add_parser("scheduled-backup-list", help="ดู scheduled backup tasks ใน Plesk")
    p.set_defaults(func=cmd_list_scheduled_backups)

    p = sub.add_parser("scheduled-backup-config", help="ตั้ง scheduled backup ผ่าน Plesk")
    p.add_argument("--frequency", choices=["hourly", "daily", "weekly", "monthly"], required=True,
                   help="ความถี่ backup")
    p.add_argument("--storage", choices=["server", "ftp", "google-drive-backup"], default="server",
                   help="ที่เก็บ backup")
    p.add_argument("--time", default="03:30", help="เวลา เช่น 03:30")
    p.add_argument("--weekday", default="sunday", choices=[
        "sunday", "monday", "tuesday", "wednesday", "thursday", "friday", "saturday"
    ], help="ใช้เมื่อ frequency=weekly")
    p.add_argument("--monthday", default="last", help="ใช้เมื่อ frequency=monthly เช่น 1, 15, last")
    p.add_argument("--incremental", action="store_true", help="เปิด incremental backup")
    p.add_argument("--exclude-mail", action="store_true", help="ไม่ backup mail")
    p.add_argument("--exclude-user-files", action="store_true", help="ไม่ backup user files")
    p.add_argument("--exclude-databases", action="store_true", help="ไม่ backup databases")
    p.add_argument("--keep-in-server-storage", choices=["true", "false"],
                   help="เก็บไว้ทั้ง server และ remote storage")
    p.add_argument("--dry-run", action="store_true", help="แสดงคำสั่งโดยไม่รันจริง")
    p.set_defaults(
        func=lambda a: cmd_configure_scheduled_backup(
            argparse.Namespace(
                **{
                    **vars(a),
                    "keep_in_server_storage":
                        None if a.keep_in_server_storage is None else (a.keep_in_server_storage == "true")
                }
            )
        )
    )

    p = sub.add_parser("plesk-help", help="เปิด help ของ utility ใน Plesk เช่น site/subscription/pleskbackup")
    p.add_argument("utility", help="เช่น site, subscription, pleskbackup, pleskrestore, scheduled-backup")
    p.set_defaults(func=cmd_plesk_help)

    return parser


def main():
    require_root()
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()