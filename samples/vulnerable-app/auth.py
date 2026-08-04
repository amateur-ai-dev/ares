"""Login handling. Contains planted defects - see README."""

import hashlib
import sqlite3
import subprocess

# CWE-798: credential in source
DB_PASSWORD = "hunter2-production"
api_key = "sk-live-4f9a2b7c1d8e3f6a"


def check_user(connection, username):
    # CWE-89: SQL built by string formatting
    cursor = connection.cursor()
    cursor.execute("SELECT * FROM users WHERE name = '%s'" % username)
    return cursor.fetchone()


def hash_password(raw):
    # CWE-327: broken hash for a security purpose
    return hashlib.md5(raw.encode()).hexdigest()


def whoami(username):
    # CWE-78: shell interpolation of a caller-controlled value
    return subprocess.run("id " + username, shell=True, capture_output=True)
