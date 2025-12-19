-- Users
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  role TEXT NOT NULL CHECK(role IN ('ADMIN','PERM_ORD','PERM_CUI','GRADE_RHL')),
  password_hash_b64 TEXT NOT NULL,
  salt_b64 TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

-- Products
CREATE TABLE IF NOT EXISTS products (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  category TEXT,
  unit TEXT NOT NULL DEFAULT 'pcs',
  stock_current REAL NOT NULL DEFAULT 0,
  stock_min REAL NOT NULL DEFAULT 0,
  location TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL
);

-- Stock movements
CREATE TABLE IF NOT EXISTS stock_movements (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  product_id INTEGER NOT NULL,
  type TEXT NOT NULL CHECK(type IN ('IN','OUT','ADJUST')),
  qty REAL NOT NULL,
  reason TEXT,
  user_id INTEGER,
  request_id INTEGER,
  created_at TEXT NOT NULL,
  FOREIGN KEY(product_id) REFERENCES products(id)
);

-- Requests
CREATE TABLE IF NOT EXISTS requests (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_by_user_id INTEGER,
  created_by_qr_token_id INTEGER,
  status TEXT NOT NULL CHECK(status IN ('PENDING','APPROVED','SERVED','REFUSED')) DEFAULT 'PENDING',
  note TEXT,
  created_at TEXT NOT NULL,
  validated_by INTEGER,
  validated_at TEXT
);

-- Request items
CREATE TABLE IF NOT EXISTS request_items (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  request_id INTEGER NOT NULL,
  product_id INTEGER NOT NULL,
  qty_requested REAL NOT NULL,
  qty_approved REAL,
  FOREIGN KEY(request_id) REFERENCES requests(id),
  FOREIGN KEY(product_id) REFERENCES products(id)
);

-- QR tokens
CREATE TABLE IF NOT EXISTS qr_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  token TEXT NOT NULL UNIQUE,
  label TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  expires_at TEXT
);
