"""
Database access layer for the Motorcycle Parts POS & Inventory System.
Wraps SQLite with helper methods used by every UI module.
"""

import os
import sqlite3
import datetime
import hashlib
import binascii

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.path.join(BASE_DIR, "motoparts_pos.db")
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")

DEFAULT_SETTINGS = {
    "store_name": "Moto Parts & Accessories",
    "store_address": "123 Rizal Street, Your City",
    "store_phone": "0917-000-0000",
    "store_email": "",
    "tax_rate": "12",
    "currency_symbol": "PHP ",
    "invoice_prefix": "INV",
    "receipt_footer": "Thank you for your purchase! No return, no exchange after 7 days.",
    "low_stock_threshold": "5",
    "last_backup": "",
}


def now_str():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def hash_password(password: str, salt: str = None):
    if salt is None:
        salt = binascii.hexlify(os.urandom(16)).decode()
    pwd_hash = hashlib.pbkdf2_hmac(
        "sha256", password.encode("utf-8"), salt.encode("utf-8"), 100_000
    )
    return binascii.hexlify(pwd_hash).decode(), salt


def verify_password(password: str, salt: str, stored_hash: str) -> bool:
    test_hash, _ = hash_password(password, salt)
    return test_hash == stored_hash


class Database:
    """Thin wrapper around sqlite3 with convenience query helpers."""

    def __init__(self, db_path=DB_PATH):
        self.db_path = db_path
        self.conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA foreign_keys = ON")
        self._init_schema()
        self._seed_defaults()

    # ---------- low level ----------
    def _init_schema(self):
        with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
            self.conn.executescript(f.read())
        self.conn.commit()

    def execute(self, query, params=()):
        cur = self.conn.cursor()
        cur.execute(query, params)
        self.conn.commit()
        return cur

    def query(self, query, params=()):
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.fetchall()

    def query_one(self, query, params=()):
        cur = self.conn.cursor()
        cur.execute(query, params)
        return cur.fetchone()

    # ---------- seed ----------
    def _seed_defaults(self):
        # default settings
        for k, v in DEFAULT_SETTINGS.items():
            row = self.query_one("SELECT value FROM settings WHERE key=?", (k,))
            if row is None:
                self.execute("INSERT INTO settings(key, value) VALUES (?,?)", (k, v))

        # default admin account
        admin = self.query_one("SELECT id FROM users WHERE username=?", ("admin",))
        if admin is None:
            pwd_hash, salt = hash_password("admin123")
            self.execute(
                """INSERT INTO users(username, password_hash, salt, full_name, role, active, created_at)
                   VALUES (?,?,?,?,?,1,?)""",
                ("admin", pwd_hash, salt, "Administrator", "admin", now_str()),
            )

        # a few starter categories
        default_cats = ["Engine Parts", "Body Parts", "Electrical", "Tires & Wheels",
                         "Oils & Fluids", "Accessories", "Helmets & Gear", "Brakes"]
        for c in default_cats:
            row = self.query_one("SELECT id FROM categories WHERE name=?", (c,))
            if row is None:
                self.execute("INSERT INTO categories(name) VALUES (?)", (c,))

    # ================= SETTINGS =================
    def get_setting(self, key, default=""):
        row = self.query_one("SELECT value FROM settings WHERE key=?", (key,))
        return row["value"] if row else default

    def get_all_settings(self):
        rows = self.query("SELECT key, value FROM settings")
        return {r["key"]: r["value"] for r in rows}

    def set_setting(self, key, value):
        self.execute(
            "INSERT INTO settings(key, value) VALUES (?,?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )

    # ================= USERS =================
    def get_user_by_username(self, username):
        return self.query_one("SELECT * FROM users WHERE username=?", (username,))

    def list_users(self):
        return self.query("SELECT * FROM users ORDER BY created_at DESC")

    def create_user(self, username, password, full_name, role):
        pwd_hash, salt = hash_password(password)
        self.execute(
            """INSERT INTO users(username, password_hash, salt, full_name, role, active, created_at)
               VALUES (?,?,?,?,?,1,?)""",
            (username, pwd_hash, salt, full_name, role, now_str()),
        )

    def update_user(self, user_id, full_name=None, role=None, active=None):
        fields, params = [], []
        if full_name is not None:
            fields.append("full_name=?"); params.append(full_name)
        if role is not None:
            fields.append("role=?"); params.append(role)
        if active is not None:
            fields.append("active=?"); params.append(1 if active else 0)
        if not fields:
            return
        params.append(user_id)
        self.execute(f"UPDATE users SET {', '.join(fields)} WHERE id=?", params)

    def reset_password(self, user_id, new_password):
        pwd_hash, salt = hash_password(new_password)
        self.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?",
                      (pwd_hash, salt, user_id))

    def delete_user(self, user_id):
        self.execute("DELETE FROM users WHERE id=?", (user_id,))

    # ================= CATEGORIES =================
    def list_categories(self):
        return self.query("SELECT * FROM categories ORDER BY name")

    def add_category(self, name):
        self.execute("INSERT OR IGNORE INTO categories(name) VALUES (?)", (name,))

    def delete_category(self, cat_id):
        self.execute("DELETE FROM categories WHERE id=?", (cat_id,))

    # ================= SUPPLIERS =================
    def list_suppliers(self, search=""):
        if search:
            like = f"%{search}%"
            return self.query(
                "SELECT * FROM suppliers WHERE name LIKE ? OR contact_person LIKE ? OR phone LIKE ? "
                "ORDER BY name", (like, like, like))
        return self.query("SELECT * FROM suppliers ORDER BY name")

    def get_supplier(self, supplier_id):
        return self.query_one("SELECT * FROM suppliers WHERE id=?", (supplier_id,))

    def add_supplier(self, name, contact_person, phone, email, address):
        self.execute(
            """INSERT INTO suppliers(name, contact_person, phone, email, address, created_at)
               VALUES (?,?,?,?,?,?)""",
            (name, contact_person, phone, email, address, now_str()))

    def update_supplier(self, supplier_id, name, contact_person, phone, email, address):
        self.execute(
            """UPDATE suppliers SET name=?, contact_person=?, phone=?, email=?, address=?
               WHERE id=?""",
            (name, contact_person, phone, email, address, supplier_id))

    def delete_supplier(self, supplier_id):
        self.execute("DELETE FROM suppliers WHERE id=?", (supplier_id,))

    # ================= CUSTOMERS =================
    def list_customers(self, search=""):
        if search:
            like = f"%{search}%"
            return self.query(
                "SELECT * FROM customers WHERE name LIKE ? OR phone LIKE ? OR email LIKE ? "
                "ORDER BY name", (like, like, like))
        return self.query("SELECT * FROM customers ORDER BY name")

    def get_customer(self, customer_id):
        return self.query_one("SELECT * FROM customers WHERE id=?", (customer_id,))

    def add_customer(self, name, phone, email, address):
        self.execute(
            "INSERT INTO customers(name, phone, email, address, created_at) VALUES (?,?,?,?,?)",
            (name, phone, email, address, now_str()))
        return self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]

    def update_customer(self, customer_id, name, phone, email, address):
        self.execute(
            "UPDATE customers SET name=?, phone=?, email=?, address=? WHERE id=?",
            (name, phone, email, address, customer_id))

    def delete_customer(self, customer_id):
        self.execute("DELETE FROM customers WHERE id=?", (customer_id,))

    # ================= PRODUCTS =================
    def list_products(self, search="", category_id=None, only_active=True, only_low_stock=False):
        query = """SELECT p.*, c.name AS category_name, s.name AS supplier_name
                   FROM products p
                   LEFT JOIN categories c ON p.category_id = c.id
                   LEFT JOIN suppliers s ON p.supplier_id = s.id
                   WHERE 1=1"""
        params = []
        if only_active:
            query += " AND p.active=1"
        if search:
            query += " AND (p.name LIKE ? OR p.sku LIKE ? OR p.barcode LIKE ?)"
            like = f"%{search}%"
            params += [like, like, like]
        if category_id:
            query += " AND p.category_id=?"
            params.append(category_id)
        if only_low_stock:
            query += " AND p.quantity <= p.reorder_level"
        query += " ORDER BY p.name"
        return self.query(query, params)

    def get_product(self, product_id):
        return self.query_one("""SELECT p.*, c.name AS category_name, s.name AS supplier_name
                                  FROM products p
                                  LEFT JOIN categories c ON p.category_id = c.id
                                  LEFT JOIN suppliers s ON p.supplier_id = s.id
                                  WHERE p.id=?""", (product_id,))

    def get_product_by_barcode_or_sku(self, code):
        return self.query_one(
            "SELECT * FROM products WHERE (barcode=? OR sku=?) AND active=1", (code, code))

    def add_product(self, sku, barcode, name, category_id, supplier_id,
                     cost_price, selling_price, quantity, reorder_level, unit, description):
        ts = now_str()
        self.execute(
            """INSERT INTO products(sku, barcode, name, category_id, supplier_id, cost_price,
               selling_price, quantity, reorder_level, unit, description, active, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,1,?,?)""",
            (sku, barcode or None, name, category_id, supplier_id, cost_price, selling_price,
             quantity, reorder_level, unit, description, ts, ts))

    def update_product(self, product_id, sku, barcode, name, category_id, supplier_id,
                        cost_price, selling_price, reorder_level, unit, description):
        self.execute(
            """UPDATE products SET sku=?, barcode=?, name=?, category_id=?, supplier_id=?,
               cost_price=?, selling_price=?, reorder_level=?, unit=?, description=?, updated_at=?
               WHERE id=?""",
            (sku, barcode or None, name, category_id, supplier_id, cost_price, selling_price,
             reorder_level, unit, description, now_str(), product_id))

    def set_product_active(self, product_id, active):
        self.execute("UPDATE products SET active=?, updated_at=? WHERE id=?",
                      (1 if active else 0, now_str(), product_id))

    def delete_product(self, product_id):
        self.execute("DELETE FROM products WHERE id=?", (product_id,))

    def adjust_stock(self, product_id, delta):
        """delta can be positive (add) or negative (deduct)."""
        self.execute("UPDATE products SET quantity = quantity + ?, updated_at=? WHERE id=?",
                      (delta, now_str(), product_id))

    def set_stock(self, product_id, new_qty):
        self.execute("UPDATE products SET quantity=?, updated_at=? WHERE id=?",
                      (new_qty, now_str(), product_id))

    def count_products(self):
        return self.query_one("SELECT COUNT(*) c FROM products WHERE active=1")["c"]

    def count_low_stock(self):
        return self.query_one(
            "SELECT COUNT(*) c FROM products WHERE active=1 AND quantity <= reorder_level")["c"]

    def inventory_value(self):
        row = self.query_one(
            "SELECT COALESCE(SUM(quantity * cost_price),0) v FROM products WHERE active=1")
        return row["v"]

    # ================= INVENTORY ADJUSTMENTS =================
    def add_inventory_adjustment(self, product_id, user_id, adj_type, quantity, reason):
        self.execute(
            """INSERT INTO inventory_adjustments(product_id, user_id, adj_type, quantity, reason, created_at)
               VALUES (?,?,?,?,?,?)""",
            (product_id, user_id, adj_type, quantity, reason, now_str()))
        if adj_type in ("Stock In", "Returned"):
            self.adjust_stock(product_id, quantity)
        elif adj_type in ("Stock Out", "Damaged"):
            self.adjust_stock(product_id, -quantity)
        elif adj_type == "Correction":
            self.set_stock(product_id, quantity)

    def list_adjustments(self, search=""):
        query = """SELECT ia.*, p.name AS product_name, p.sku, u.full_name AS user_name
                   FROM inventory_adjustments ia
                   JOIN products p ON ia.product_id = p.id
                   JOIN users u ON ia.user_id = u.id"""
        params = []
        if search:
            query += " WHERE p.name LIKE ? OR p.sku LIKE ?"
            like = f"%{search}%"
            params = [like, like]
        query += " ORDER BY ia.created_at DESC LIMIT 500"
        return self.query(query, params)

    # ================= SALES / POS =================
    def next_invoice_number(self):
        prefix = self.get_setting("invoice_prefix", "INV")
        today = datetime.date.today().strftime("%Y%m%d")
        row = self.query_one(
            "SELECT COUNT(*) c FROM sales WHERE invoice_number LIKE ?",
            (f"{prefix}-{today}-%",))
        seq = (row["c"] or 0) + 1
        return f"{prefix}-{today}-{seq:04d}"

    def create_sale(self, customer_id, user_id, items, subtotal, discount_amount,
                     tax_rate, tax_amount, total, payment_method, amount_paid, change_due):
        """items: list of dicts with product_id, product_name, sku, quantity, unit_price, discount, line_total"""
        invoice_number = self.next_invoice_number()
        cur = self.conn.cursor()
        cur.execute(
            """INSERT INTO sales(invoice_number, customer_id, user_id, subtotal, discount_amount,
               tax_rate, tax_amount, total, payment_method, amount_paid, change_due, status, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?, 'Completed', ?)""",
            (invoice_number, customer_id, user_id, subtotal, discount_amount, tax_rate,
             tax_amount, total, payment_method, amount_paid, change_due, now_str()))
        sale_id = cur.lastrowid
        for it in items:
            cur.execute(
                """INSERT INTO sale_items(sale_id, product_id, product_name, sku, quantity,
                   unit_price, discount, line_total) VALUES (?,?,?,?,?,?,?,?)""",
                (sale_id, it["product_id"], it["product_name"], it.get("sku", ""),
                 it["quantity"], it["unit_price"], it.get("discount", 0), it["line_total"]))
            if it.get("product_id"):
                cur.execute("UPDATE products SET quantity = quantity - ?, updated_at=? WHERE id=?",
                             (it["quantity"], now_str(), it["product_id"]))
        self.conn.commit()
        return sale_id, invoice_number

    def get_sale(self, sale_id):
        return self.query_one("""SELECT s.*, c.name AS customer_name, u.full_name AS cashier_name
                                  FROM sales s
                                  LEFT JOIN customers c ON s.customer_id = c.id
                                  JOIN users u ON s.user_id = u.id
                                  WHERE s.id=?""", (sale_id,))

    def get_sale_by_invoice(self, invoice_number):
        return self.query_one("""SELECT s.*, c.name AS customer_name, u.full_name AS cashier_name
                                  FROM sales s
                                  LEFT JOIN customers c ON s.customer_id = c.id
                                  JOIN users u ON s.user_id = u.id
                                  WHERE s.invoice_number=?""", (invoice_number,))

    def get_sale_items(self, sale_id):
        return self.query("SELECT * FROM sale_items WHERE sale_id=?", (sale_id,))

    def list_sales(self, date_from=None, date_to=None, search="", user_id=None):
        query = """SELECT s.*, c.name AS customer_name, u.full_name AS cashier_name
                   FROM sales s
                   LEFT JOIN customers c ON s.customer_id = c.id
                   JOIN users u ON s.user_id = u.id
                   WHERE 1=1"""
        params = []
        if date_from:
            query += " AND date(s.created_at) >= date(?)"
            params.append(date_from)
        if date_to:
            query += " AND date(s.created_at) <= date(?)"
            params.append(date_to)
        if search:
            query += " AND (s.invoice_number LIKE ? OR c.name LIKE ?)"
            like = f"%{search}%"
            params += [like, like]
        if user_id:
            query += " AND s.user_id=?"
            params.append(user_id)
        query += " ORDER BY s.created_at DESC"
        return self.query(query, params)

    def sales_summary(self, date_from, date_to):
        row = self.query_one(
            """SELECT COUNT(*) n, COALESCE(SUM(total),0) revenue,
                      COALESCE(SUM(discount_amount),0) discounts,
                      COALESCE(SUM(tax_amount),0) tax
               FROM sales WHERE date(created_at) BETWEEN date(?) AND date(?)""",
            (date_from, date_to))
        return row

    def sales_total_for_today(self):
        today = datetime.date.today().isoformat()
        row = self.query_one(
            "SELECT COALESCE(SUM(total),0) v, COUNT(*) n FROM sales WHERE date(created_at)=date(?)",
            (today,))
        return row

    def top_selling_products(self, date_from, date_to, limit=5):
        return self.query(
            """SELECT si.product_name, SUM(si.quantity) qty, SUM(si.line_total) revenue
               FROM sale_items si JOIN sales s ON si.sale_id = s.id
               WHERE date(s.created_at) BETWEEN date(?) AND date(?)
               GROUP BY si.product_name ORDER BY qty DESC LIMIT ?""",
            (date_from, date_to, limit))

    def sales_by_day(self, date_from, date_to):
        return self.query(
            """SELECT date(created_at) d, COALESCE(SUM(total),0) revenue, COUNT(*) n
               FROM sales WHERE date(created_at) BETWEEN date(?) AND date(?)
               GROUP BY date(created_at) ORDER BY d""",
            (date_from, date_to))

    def close(self):
        self.conn.close()
