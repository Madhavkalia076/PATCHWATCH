"""
A deliberately vulnerable sample app.
Used only to test PatchWatch's scanning + scoring pipeline.
"""
import sqlite3
import subprocess
from fastapi import FastAPI

app = FastAPI()

DB_PATH = "users.db"


def get_connection():
    return sqlite3.connect(DB_PATH)


@app.get("/user")
def get_user(username: str):
    # VULNERABLE: user input concatenated directly into SQL (SQL Injection)
    conn = get_connection()
    query = "SELECT * FROM users WHERE username = '" + username + "'"
    cursor = conn.execute(query)
    return cursor.fetchall()


@app.get("/ping")
def ping_host(host: str):
    # VULNERABLE: user input passed to shell (Command Injection)
    result = subprocess.run("ping -c 1 " + host, shell=True, capture_output=True)
    return result.stdout


def internal_debug_helper():
    # Same SQLi pattern, but NOT reachable from any route -> should score LOWER
    conn = get_connection()
    query = "SELECT * FROM users WHERE username = '" + "test" + "'"
    return conn.execute(query).fetchall()


API_KEY = "sk-test-hardcoded-secret-12345"  # VULNERABLE: hardcoded secret


@app.get("/lookup")
def lookup_user(user_id: str):
    # VULNERABLE: new endpoint, same SQL injection pattern as get_user above --
    # this is what the PR-gate demo is meant to catch.
    conn = get_connection()
    query = "SELECT * FROM users WHERE id = '" + user_id + "'"
    return conn.execute(query).fetchall()
