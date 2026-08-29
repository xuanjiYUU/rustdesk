PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL COLLATE NOCASE UNIQUE,
    display_name TEXT NOT NULL DEFAULT '',
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS address_books (
    guid TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    owner_user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL CHECK(kind IN ('personal', 'global')),
    created_at INTEGER NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_personal_book_owner
    ON address_books(owner_user_id)
    WHERE kind = 'personal';

CREATE TABLE IF NOT EXISTS peers (
    address_book_guid TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    peer_id TEXT NOT NULL,
    hash TEXT NOT NULL DEFAULT '',
    encrypted_password TEXT NOT NULL DEFAULT '',
    username TEXT NOT NULL DEFAULT '',
    hostname TEXT NOT NULL DEFAULT '',
    platform TEXT NOT NULL DEFAULT '',
    alias TEXT NOT NULL DEFAULT '',
    tags_json TEXT NOT NULL DEFAULT '[]',
    note TEXT NOT NULL DEFAULT '',
    created_by INTEGER NOT NULL REFERENCES users(id),
    updated_at INTEGER NOT NULL,
    PRIMARY KEY(address_book_guid, peer_id)
);

CREATE TABLE IF NOT EXISTS tags (
    address_book_guid TEXT NOT NULL REFERENCES address_books(guid) ON DELETE CASCADE,
    name TEXT NOT NULL,
    color INTEGER NOT NULL,
    PRIMARY KEY(address_book_guid, name)
);
