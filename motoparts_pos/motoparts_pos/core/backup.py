"""Backup / restore helpers for the SQLite database file."""

import os
import shutil
import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
BACKUPS_DIR = os.path.join(BASE_DIR, "backups")
os.makedirs(BACKUPS_DIR, exist_ok=True)


def backup_database(db_path, dest_folder=BACKUPS_DIR):
    os.makedirs(dest_folder, exist_ok=True)
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"motoparts_pos_backup_{timestamp}.db"
    dest_path = os.path.join(dest_folder, filename)
    shutil.copy2(db_path, dest_path)
    return dest_path


def restore_database(backup_path, db_path):
    # keep a safety copy of the current db before overwriting
    if os.path.exists(db_path):
        safety = db_path + ".before_restore.bak"
        shutil.copy2(db_path, safety)
    shutil.copy2(backup_path, db_path)
    return db_path


def list_backups(dest_folder=BACKUPS_DIR):
    if not os.path.isdir(dest_folder):
        return []
    files = [f for f in os.listdir(dest_folder) if f.endswith(".db")]
    files.sort(reverse=True)
    return [os.path.join(dest_folder, f) for f in files]
