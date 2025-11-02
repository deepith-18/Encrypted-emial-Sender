# database/db_manager.py
import sqlite3
from config import Config

def get_db_connection():
    conn = sqlite3.connect(Config.DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    with open('database/schema.sql') as f:
        conn.executescript(f.read())
    conn.close()