use std::{
    path::Path,
    sync::{Mutex, MutexGuard},
};

use anyhow::{Context, Result};
use rusqlite::{params, Connection, OptionalExtension};
use uuid::Uuid;

use crate::{
    crypto::{token_hash, Crypto},
    model::{AddressBookProfile, Page, PeerPayload, PeerUpdate, TagPayload, User},
    unix_time,
};

pub const GLOBAL_BOOK_GUID: &str = "global-shared-devices";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BookKind {
    Personal,
    Global,
}

pub struct Database {
    connection: Mutex<Connection>,
}

impl Database {
    pub fn open(path: &Path, global_book_name: &str) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }
        let connection =
            Connection::open(path).with_context(|| format!("failed to open {}", path.display()))?;
        connection
            .execute_batch(include_str!("../migrations/0001_init.sql"))
            .context("database migration failed")?;
        connection.execute(
            "INSERT OR IGNORE INTO address_books(guid, name, owner_user_id, kind, created_at)
             VALUES (?1, ?2, NULL, 'global', ?3)",
            params![GLOBAL_BOOK_GUID, global_book_name, unix_time()],
        )?;
        connection.execute(
            "UPDATE address_books SET name = ?1 WHERE guid = ?2",
            params![global_book_name, GLOBAL_BOOK_GUID],
        )?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    fn connection(&self) -> Result<MutexGuard<'_, Connection>> {
        self.connection
            .lock()
            .map_err(|_| anyhow::anyhow!("database lock was poisoned"))
    }

    pub fn user_exists(&self, username: &str) -> Result<bool> {
        let connection = self.connection()?;
        let found = connection
            .query_row(
                "SELECT 1 FROM users WHERE username = ?1",
                [username],
                |_| Ok(()),
            )
            .optional()?
            .is_some();
        Ok(found)
    }

    pub fn create_user(
        &self,
        username: &str,
        display_name: &str,
        password_hash: &str,
    ) -> Result<User> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        transaction.execute(
            "INSERT INTO users(username, display_name, password_hash, created_at)
             VALUES (?1, ?2, ?3, ?4)",
            params![username, display_name, password_hash, unix_time()],
        )?;
        let user_id = transaction.last_insert_rowid();
        transaction.execute(
            "INSERT INTO address_books(guid, name, owner_user_id, kind, created_at)
             VALUES (?1, ?2, ?3, 'personal', ?4)",
            params![
                Uuid::new_v4().to_string(),
                format!("personal-{user_id}"),
                user_id,
                unix_time()
            ],
        )?;
        transaction.commit()?;
        Ok(User {
            id: user_id,
            username: username.to_owned(),
            display_name: display_name.to_owned(),
        })
    }

    pub fn login_record(&self, username: &str) -> Result<Option<(User, String)>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT id, username, display_name, password_hash
                 FROM users WHERE username = ?1",
                [username],
                |row| {
                    Ok((
                        User {
                            id: row.get(0)?,
                            username: row.get(1)?,
                            display_name: row.get(2)?,
                        },
                        row.get(3)?,
                    ))
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn create_session(&self, user_id: i64, token: &str, expires_at: i64) -> Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO sessions(token_hash, user_id, expires_at) VALUES (?1, ?2, ?3)",
            params![token_hash(token), user_id, expires_at],
        )?;
        Ok(())
    }

    pub fn user_by_token(&self, token: &str) -> Result<Option<User>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT users.id, users.username, users.display_name
                 FROM sessions
                 JOIN users ON users.id = sessions.user_id
                 WHERE sessions.token_hash = ?1 AND sessions.expires_at > ?2",
                params![token_hash(token), unix_time()],
                |row| {
                    Ok(User {
                        id: row.get(0)?,
                        username: row.get(1)?,
                        display_name: row.get(2)?,
                    })
                },
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn delete_session(&self, token: &str) -> Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "DELETE FROM sessions WHERE token_hash = ?1",
            [token_hash(token)],
        )?;
        Ok(())
    }

    pub fn personal_guid(&self, user_id: i64) -> Result<Option<String>> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT guid FROM address_books WHERE kind = 'personal' AND owner_user_id = ?1",
                [user_id],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    pub fn global_profile(&self) -> Result<AddressBookProfile> {
        let connection = self.connection()?;
        connection
            .query_row(
                "SELECT guid, name FROM address_books WHERE guid = ?1",
                [GLOBAL_BOOK_GUID],
                |row| {
                    Ok(AddressBookProfile {
                        guid: row.get(0)?,
                        name: row.get(1)?,
                        owner: "All accounts".to_owned(),
                        note: "Visible and writable by every signed-in account".to_owned(),
                        rule: 3,
                        info: serde_json::json!({}),
                    })
                },
            )
            .map_err(Into::into)
    }

    pub fn book_kind_for_user(&self, guid: &str, user_id: i64) -> Result<Option<BookKind>> {
        let connection = self.connection()?;
        let row: Option<(String, Option<i64>)> = connection
            .query_row(
                "SELECT kind, owner_user_id FROM address_books WHERE guid = ?1",
                [guid],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(match row {
            Some((kind, _)) if kind == "global" => Some(BookKind::Global),
            Some((kind, Some(owner))) if kind == "personal" && owner == user_id => {
                Some(BookKind::Personal)
            }
            _ => None,
        })
    }

    pub fn list_peers(
        &self,
        guid: &str,
        limit: i64,
        offset: i64,
        crypto: &Crypto,
    ) -> Result<Page<PeerPayload>> {
        let connection = self.connection()?;
        let total = connection.query_row(
            "SELECT COUNT(*) FROM peers WHERE address_book_guid = ?1",
            [guid],
            |row| row.get(0),
        )?;
        let mut statement = connection.prepare(
            "SELECT peer_id, hash, encrypted_password, username, hostname, platform,
                    alias, tags_json, note
             FROM peers WHERE address_book_guid = ?1
             ORDER BY lower(alias), peer_id LIMIT ?2 OFFSET ?3",
        )?;
        let rows = statement.query_map(params![guid, limit, offset], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, String>(6)?,
                row.get::<_, String>(7)?,
                row.get::<_, String>(8)?,
            ))
        })?;
        let mut peers = Vec::new();
        for row in rows {
            let (id, hash, encrypted_password, username, hostname, platform, alias, tags, note) =
                row?;
            peers.push(PeerPayload {
                id,
                hash,
                password: crypto.decrypt(&encrypted_password)?,
                username,
                hostname,
                platform,
                alias,
                tags: serde_json::from_str(&tags).unwrap_or_default(),
                note,
                same_server: Some(true),
            });
        }
        Ok(Page { total, data: peers })
    }

    pub fn peer_exists(&self, guid: &str, peer_id: &str) -> Result<bool> {
        let connection = self.connection()?;
        Ok(connection
            .query_row(
                "SELECT 1 FROM peers WHERE address_book_guid = ?1 AND peer_id = ?2",
                params![guid, peer_id],
                |_| Ok(()),
            )
            .optional()?
            .is_some())
    }

    pub fn add_peer(
        &self,
        guid: &str,
        user_id: i64,
        peer: &PeerPayload,
        password: &str,
        crypto: &Crypto,
    ) -> Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO peers(
                address_book_guid, peer_id, hash, encrypted_password, username,
                hostname, platform, alias, tags_json, note, created_by, updated_at
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                guid,
                peer.id,
                peer.hash,
                crypto.encrypt(password)?,
                peer.username,
                peer.hostname,
                peer.platform,
                peer.alias,
                serde_json::to_string(&peer.tags)?,
                peer.note,
                user_id,
                unix_time(),
            ],
        )?;
        Ok(())
    }

    pub fn update_peer(&self, guid: &str, update: PeerUpdate, crypto: &Crypto) -> Result<bool> {
        let connection = self.connection()?;
        let existing = connection
            .query_row(
                "SELECT hash, encrypted_password, username, hostname, platform, alias, tags_json, note
                 FROM peers WHERE address_book_guid = ?1 AND peer_id = ?2",
                params![guid, update.id],
                |row| {
                    Ok((
                        row.get::<_, String>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                        row.get::<_, String>(5)?,
                        row.get::<_, String>(6)?,
                        row.get::<_, String>(7)?,
                    ))
                },
            )
            .optional()?;
        let Some((hash, encrypted_password, username, hostname, platform, alias, tags, note)) =
            existing
        else {
            return Ok(false);
        };
        connection.execute(
            "UPDATE peers SET hash = ?3, encrypted_password = ?4, username = ?5,
                hostname = ?6, platform = ?7, alias = ?8, tags_json = ?9,
                note = ?10, updated_at = ?11
             WHERE address_book_guid = ?1 AND peer_id = ?2",
            params![
                guid,
                update.id,
                update.hash.unwrap_or(hash),
                match update.password {
                    Some(password) => crypto.encrypt(&password)?,
                    None => encrypted_password,
                },
                update.username.unwrap_or(username),
                update.hostname.unwrap_or(hostname),
                update.platform.unwrap_or(platform),
                update.alias.unwrap_or(alias),
                match update.tags {
                    Some(tags) => serde_json::to_string(&tags)?,
                    None => tags,
                },
                update.note.unwrap_or(note),
                unix_time(),
            ],
        )?;
        Ok(true)
    }

    pub fn delete_peers(&self, guid: &str, peer_ids: &[String]) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        for peer_id in peer_ids {
            transaction.execute(
                "DELETE FROM peers WHERE address_book_guid = ?1 AND peer_id = ?2",
                params![guid, peer_id],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }

    pub fn list_tags(&self, guid: &str) -> Result<Vec<TagPayload>> {
        let connection = self.connection()?;
        let mut statement = connection.prepare(
            "SELECT name, color FROM tags WHERE address_book_guid = ?1 ORDER BY lower(name)",
        )?;
        let rows = statement.query_map([guid], |row| {
            Ok(TagPayload {
                name: row.get(0)?,
                color: row.get(1)?,
            })
        })?;
        rows.collect::<Result<Vec<_>, _>>().map_err(Into::into)
    }

    pub fn add_tag(&self, guid: &str, tag: &TagPayload) -> Result<()> {
        let connection = self.connection()?;
        connection.execute(
            "INSERT INTO tags(address_book_guid, name, color) VALUES (?1, ?2, ?3)",
            params![guid, tag.name, tag.color],
        )?;
        Ok(())
    }

    pub fn update_tag(&self, guid: &str, tag: &TagPayload) -> Result<bool> {
        let connection = self.connection()?;
        Ok(connection.execute(
            "UPDATE tags SET color = ?3 WHERE address_book_guid = ?1 AND name = ?2",
            params![guid, tag.name, tag.color],
        )? > 0)
    }

    pub fn rename_tag(&self, guid: &str, old: &str, new: &str) -> Result<bool> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        let changed = transaction.execute(
            "UPDATE tags SET name = ?3 WHERE address_book_guid = ?1 AND name = ?2",
            params![guid, old, new],
        )?;
        if changed > 0 {
            let mut statement = transaction
                .prepare("SELECT peer_id, tags_json FROM peers WHERE address_book_guid = ?1")?;
            let rows = statement.query_map([guid], |row| {
                Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
            })?;
            let mut replacements = Vec::new();
            for row in rows {
                let (peer_id, tags_json) = row?;
                let mut tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
                let mut replaced = false;
                for tag in &mut tags {
                    if tag == old {
                        *tag = new.to_owned();
                        replaced = true;
                    }
                }
                if replaced {
                    replacements.push((peer_id, serde_json::to_string(&tags)?));
                }
            }
            drop(statement);
            for (peer_id, tags_json) in replacements {
                transaction.execute(
                    "UPDATE peers SET tags_json = ?3 WHERE address_book_guid = ?1 AND peer_id = ?2",
                    params![guid, peer_id, tags_json],
                )?;
            }
        }
        transaction.commit()?;
        Ok(changed > 0)
    }

    pub fn delete_tags(&self, guid: &str, names: &[String]) -> Result<()> {
        let mut connection = self.connection()?;
        let transaction = connection.transaction()?;
        for name in names {
            transaction.execute(
                "DELETE FROM tags WHERE address_book_guid = ?1 AND name = ?2",
                params![guid, name],
            )?;
        }
        let mut statement = transaction
            .prepare("SELECT peer_id, tags_json FROM peers WHERE address_book_guid = ?1")?;
        let rows = statement.query_map([guid], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })?;
        let mut replacements = Vec::new();
        for row in rows {
            let (peer_id, tags_json) = row?;
            let mut tags: Vec<String> = serde_json::from_str(&tags_json).unwrap_or_default();
            let old_len = tags.len();
            tags.retain(|tag| !names.contains(tag));
            if tags.len() != old_len {
                replacements.push((peer_id, serde_json::to_string(&tags)?));
            }
        }
        drop(statement);
        for (peer_id, tags_json) in replacements {
            transaction.execute(
                "UPDATE peers SET tags_json = ?3 WHERE address_book_guid = ?1 AND peer_id = ?2",
                params![guid, peer_id, tags_json],
            )?;
        }
        transaction.commit()?;
        Ok(())
    }
}
