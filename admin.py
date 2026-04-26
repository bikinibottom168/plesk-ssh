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


def safe_sql_value(val: str) -> str:
    if not val:
        raise ValueError("ค่าว่างไม่ได้")
    bad = ["'", '"', ";", "\\", "\x00", "\n", "\r", "`"]
    if any(c in val for c in bad):
        raise ValueError(f"พบอักขระต้องห้ามในค่า: {val}")
    return val


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


def cmd_view_ftp(args):
    if args.all:
        sql = (
            "SELECT IFNULL(d.name, '-') AS domain, s.login, a.password, a.type "
            "FROM sys_users s "
            "JOIN accounts a ON s.account_id = a.id "
            "LEFT JOIN domains d ON d.sys_user_id = s.id "
            "ORDER BY d.name, s.login"
        )
    elif args.user:
        user = safe_sql_value(args.user)
        sql = (
            "SELECT IFNULL(d.name, '-') AS domain, s.login, a.password, a.type "
            "FROM sys_users s "
            "JOIN accounts a ON s.account_id = a.id "
            "LEFT JOIN domains d ON d.sys_user_id = s.id "
            f"WHERE s.login = '{user}'"
        )
    elif args.domain:
        domain = safe_sql_value(args.domain)
        sql = (
            "SELECT d.name AS domain, s.login, a.password, a.type "
            "FROM domains d "
            "JOIN sys_users s ON d.sys_user_id = s.id "
            "JOIN accounts a ON s.account_id = a.id "
            f"WHERE d.name = '{domain}'"
        )
    else:
        eprint("ERROR: ต้องระบุ domain หรือ --user หรือ --all")
        sys.exit(1)

    cmd = ["plesk", "db", "-N", "-B", "-e", sql]
    proc = run_cmd(cmd, check=True, capture_output=True)

    rows = [line for line in proc.stdout.splitlines() if line.strip()]
    if not rows:
        print("ไม่พบข้อมูล FTP")
        return

    print(f"{'domain':<28} {'ftp_user':<22} {'password':<40} type")
    print("-" * 105)
    for line in rows:
        parts = line.split("\t")
        while len(parts) < 4:
            parts.append("")
        d, login, pwd, ptype = parts[:4]
        print(f"{d:<28} {login:<22} {pwd:<40} {ptype}")
    print(
        "\nหมายเหตุ: ถ้า type ไม่ใช่ 'plain' ให้ถอดรหัสด้วย "
        "/usr/local/psa/admin/sbin/encrypt3"
    )


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
            "  admin.py view-ftp example.com\n"
            "  admin.py view-ftp --user webuser1\n"
            "  admin.py view-ftp --all\n"
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

    p = sub.add_parser("view-ftp", help="ดูรหัสผ่าน FTP ของโดเมน/ผู้ใช้")
    p.add_argument("domain", nargs="?", help="ชื่อโดเมน (ไม่ต้องใส่ถ้าใช้ --user หรือ --all)")
    p.add_argument("--user", help="ระบุชื่อ FTP user")
    p.add_argument("--all", action="store_true", help="แสดงทั้งหมด")
    p.set_defaults(func=cmd_view_ftp)

    return parser


def prompt(label, default=None, required=True):
    suffix = f" [{default}]" if default not in (None, "") else ""
    while True:
        try:
            val = input(f"{label}{suffix}: ").strip()
        except EOFError:
            print()
            return default if default is not None else ""
        if val:
            return val
        if default is not None:
            return default
        if not required:
            return ""
        print("กรุณากรอกค่า")


def prompt_yes_no(label, default=False):
    suffix = "[Y/n]" if default else "[y/N]"
    try:
        val = input(f"{label} {suffix}: ").strip().lower()
    except EOFError:
        print()
        return default
    if not val:
        return default
    return val in ("y", "yes")


def menu_list():
    cmd_list(argparse.Namespace())


def menu_rename_domain():
    old = prompt("โดเมนเดิม")
    new = prompt("โดเมนใหม่")
    dry = prompt_yes_no("Dry run?", default=False)
    cmd_rename_domain(argparse.Namespace(old_domain=old, new_domain=new, dry_run=dry))


def menu_backup_subscription():
    domain = prompt("ชื่อโดเมน/subscription")
    default_out = f"/root/backups/{safe_filename(domain)}_{now_ts()}.tar"
    output = prompt("ไฟล์ปลายทาง", default=default_out)
    incremental = prompt_yes_no("Incremental?", default=False)
    keep_local = prompt_yes_no("Keep local backup?", default=False)
    dry = prompt_yes_no("Dry run?", default=False)
    cmd_backup_subscription(argparse.Namespace(
        domain=domain, output=output, incremental=incremental,
        keep_local_backup=keep_local, verbose=0, dry_run=dry,
    ))


def menu_restore_subscription():
    backup_file = prompt("ไฟล์ backup")
    only = prompt("Restore อะไร? (all/databases/web/dns)", default="all")
    domain = ""
    if only in ("databases", "web", "dns"):
        domain = prompt("ชื่อโดเมน")
    config_only = prompt_yes_no("Configuration only?", default=False)
    content_only = prompt_yes_no("Content only?", default=False)
    verbose = prompt_yes_no("Verbose?", default=False)
    dry = prompt_yes_no("Dry run?", default=False)
    cmd_restore_subscription(argparse.Namespace(
        backup_file=backup_file, only=only, domain=domain or None,
        configuration_only=config_only, content_only=content_only,
        verbose=verbose, dry_run=dry,
    ))


def menu_backup_site_files():
    domain = prompt("ชื่อโดเมน")
    output_dir = prompt("โฟลเดอร์เก็บ backup", default="/root/backups")
    vhosts_root = prompt("Vhosts root", default=DEFAULT_VHOSTS_ROOT)
    source = prompt("Source path (เว้นว่างเพื่อใช้ httpdocs)", default="", required=False)
    exclude_str = prompt("Exclude (คั่นด้วย comma)", default="", required=False)
    exclude = [x.strip() for x in exclude_str.split(",") if x.strip()] if exclude_str else []
    dry = prompt_yes_no("Dry run?", default=False)
    cmd_backup_site_files(argparse.Namespace(
        domain=domain, output_dir=output_dir, vhosts_root=vhosts_root,
        source=source or None, exclude=exclude, dry_run=dry,
    ))


def menu_backup_db():
    db_name = prompt("ชื่อฐานข้อมูล")
    db_user = prompt("DB user")
    db_pass = prompt("DB password")
    host = prompt("DB host", default="127.0.0.1")
    port = prompt("DB port", default="3306")
    engine = prompt("Engine (mysql/mariadb)", default="mysql")
    output_dir = prompt("โฟลเดอร์เก็บ backup", default="/root/backups")
    gzip_v = prompt_yes_no("Gzip?", default=True)
    dry = prompt_yes_no("Dry run?", default=False)
    cmd_backup_db(argparse.Namespace(
        db_name=db_name, db_user=db_user, db_pass=db_pass,
        host=host, port=port, engine=engine,
        output_dir=output_dir, gzip=gzip_v, dry_run=dry,
    ))


def menu_view_ftp():
    print("  1) ดูตามโดเมน")
    print("  2) ดูตามชื่อ user")
    print("  3) แสดงทั้งหมด")
    choice = prompt("เลือก", default="1")
    domain = user = None
    all_flag = False
    if choice == "1":
        domain = prompt("ชื่อโดเมน")
    elif choice == "2":
        user = prompt("ชื่อ FTP user")
    elif choice == "3":
        all_flag = True
    else:
        print("ตัวเลือกไม่ถูกต้อง")
        return
    cmd_view_ftp(argparse.Namespace(domain=domain, user=user, all=all_flag))


def menu_scheduled_list():
    cmd_list_scheduled_backups(argparse.Namespace())


def menu_scheduled_config():
    frequency = prompt("Frequency (hourly/daily/weekly/monthly)", default="daily")
    storage = prompt("Storage (server/ftp/google-drive-backup)", default="server")
    time_v = prompt("เวลา", default="03:30")
    weekday = "sunday"
    monthday = "last"
    if frequency == "weekly":
        weekday = prompt("วัน", default="sunday")
    if frequency == "monthly":
        monthday = prompt("วันที่ของเดือน (1-31 หรือ last)", default="last")
    incremental = prompt_yes_no("Incremental?", default=False)
    excl_mail = prompt_yes_no("Exclude mail?", default=False)
    excl_user = prompt_yes_no("Exclude user files?", default=False)
    excl_db = prompt_yes_no("Exclude databases?", default=False)
    keep_in_server = prompt("Keep in server storage? (true/false/ว่าง)", default="", required=False)
    keep_val = None if not keep_in_server else (keep_in_server.lower() == "true")
    dry = prompt_yes_no("Dry run?", default=False)
    cmd_configure_scheduled_backup(argparse.Namespace(
        frequency=frequency, storage=storage, time=time_v,
        weekday=weekday, monthday=monthday,
        incremental=incremental, exclude_mail=excl_mail,
        exclude_user_files=excl_user, exclude_databases=excl_db,
        keep_in_server_storage=keep_val, dry_run=dry,
    ))


def menu_plesk_help():
    utility = prompt("Utility (เช่น site, subscription, pleskbackup)")
    cmd_plesk_help(argparse.Namespace(utility=utility))


MENU_ITEMS = [
    ("1", "List domains", menu_list),
    ("2", "Rename domain", menu_rename_domain),
    ("3", "Backup subscription", menu_backup_subscription),
    ("4", "Restore subscription", menu_restore_subscription),
    ("5", "Backup site files", menu_backup_site_files),
    ("6", "Backup database", menu_backup_db),
    ("7", "ดูรหัส FTP", menu_view_ftp),
    ("8", "List scheduled backups", menu_scheduled_list),
    ("9", "Configure scheduled backup", menu_scheduled_config),
    ("10", "Plesk help", menu_plesk_help),
    ("0", "ออก", None),
]


def interactive_menu():
    while True:
        print("\n=== Plesk Admin Menu ===")
        for key, label, _ in MENU_ITEMS:
            print(f"  {key}) {label}")
        try:
            choice = input("\nเลือกหมายเลข: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        for key, _label, action in MENU_ITEMS:
            if choice == key:
                if action is None:
                    return
                try:
                    action()
                except KeyboardInterrupt:
                    print("\nยกเลิก")
                except SystemExit as e:
                    if e.code:
                        eprint(f"คำสั่งล้มเหลว (exit {e.code})")
                except Exception as e:
                    eprint(f"ERROR: {e}")
                break
        else:
            print("ตัวเลือกไม่ถูกต้อง")


def main():
    require_root()
    if len(sys.argv) == 1:
        interactive_menu()
        return
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()