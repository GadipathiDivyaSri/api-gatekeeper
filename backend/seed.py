"""
DemoShop Database Seeder (Module M1).
Recreates data/demoshop.db with parameterized initial records for users and products.
"""

from __future__ import annotations

import hashlib
import os
import sqlite3
from pathlib import Path


def get_db_path() -> Path:
    """Return database path honoring DATA_DIR environment variable."""
    data_dir = Path(os.getenv("DATA_DIR", "data"))
    return data_dir / "demoshop.db"


def hash_password(password: str, salt: bytes | None = None) -> str:
    """Hash password using PBKDF2-HMAC-SHA256 with salt."""
    if salt is None:
        salt = os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
    return f"{salt.hex()}${dk.hex()}"


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify password against stored salt$hash in constant time."""
    try:
        salt_hex, hash_hex = stored_hash.split("$", 1)
        salt = bytes.fromhex(salt_hex)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100_000)
        import hmac

        return hmac.compare_digest(dk.hex(), hash_hex)
    except Exception:
        return False


USERS_SEED = [
    ("admin", "admin@demoshop.test", "AdminSecurePass123!", "admin"),
    ("alice", "alice@demoshop.test", "AlicePass123!", "customer"),
    ("bob", "bob@demoshop.test", "BobPass123!", "customer"),
    ("carol", "carol@demoshop.test", "CarolPass123!", "customer"),
    ("dave", "dave@demoshop.test", "DavePass123!", "staff"),
]

PRODUCTS_SEED = [
    ("Smartphone X", "electronics", 799.99, 45),
    ("Noise-Cancelling Headphones", "electronics", 199.99, 120),
    ("Wireless Mechanical Keyboard", "electronics", 89.99, 80),
    ("Ultra HD 4K Monitor", "electronics", 349.50, 25),
    ("Python Programming Handbook", "books", 39.99, 200),
    ("Web Security & Penetration Testing", "books", 49.99, 150),
    ("Cloud Native Architecture", "books", 54.00, 75),
    ("Classic Cotton T-Shirt", "clothing", 19.99, 300),
    ("Waterproof Hiking Jacket", "clothing", 129.99, 60),
    ("Ergonomic Office Chair", "furniture", 249.99, 40),
    ("Stainless Steel Water Bottle", "accessories", 24.50, 180),
    ("USB-C Multiport Adapter", "accessories", 35.00, 110),
]


def seed_database(db_path: Path | None = None) -> None:
    """Recreate and populate demoshop.db with initial seed data."""
    target_path = db_path or get_db_path()
    target_path.parent.mkdir(parents=True, exist_ok=True)

    conn = sqlite3.connect(target_path)
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute("PRAGMA foreign_keys = ON;")

            # Drop existing tables cleanly
            cursor.execute("DROP TABLE IF EXISTS feedback;")
            cursor.execute("DROP TABLE IF EXISTS products;")
            cursor.execute("DROP TABLE IF EXISTS users;")

            # Create tables
            cursor.execute(
                """
                CREATE TABLE users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    email TEXT NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL
                );
                """
            )

            cursor.execute(
                """
                CREATE TABLE products (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT NOT NULL,
                    category TEXT NOT NULL,
                    price REAL NOT NULL,
                    stock INTEGER NOT NULL
                );
                """
            )

            cursor.execute(
                """
                CREATE TABLE feedback (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    product_id INTEGER NOT NULL,
                    comment TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY(product_id) REFERENCES products(id)
                );
                """
            )

            # Insert users
            user_records = [
                (uname, email, hash_password(pwd), role)
                for uname, email, pwd, role in USERS_SEED
            ]
            cursor.executemany(
                "INSERT INTO users (username, email, password_hash, role) VALUES (?, ?, ?, ?);",
                user_records,
            )

            # Insert products
            cursor.executemany(
                "INSERT INTO products (name, category, price, stock) VALUES (?, ?, ?, ?);",
                PRODUCTS_SEED,
            )

        print(
            f"[DEMOSHOP] Database seeded successfully at {target_path}: "
            f"{len(USERS_SEED)} users, {len(PRODUCTS_SEED)} products."
        )
    finally:
        conn.close()


if __name__ == "__main__":
    seed_database()
