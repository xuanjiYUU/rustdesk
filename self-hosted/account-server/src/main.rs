mod crypto;
mod db;
mod error;
mod handlers;
mod model;

use std::{
    env,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result};
use axum::{
    routing::{delete, get, post, put},
    Router,
};
use axum_server::{tls_rustls::RustlsConfig, Handle};
use crypto::Crypto;
use db::Database;
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct AppState {
    database: Arc<Database>,
    crypto: Arc<Crypto>,
    allow_registration: bool,
    session_lifetime_seconds: i64,
}

struct Config {
    bind: SocketAddr,
    database_path: PathBuf,
    tls_cert: PathBuf,
    tls_key: PathBuf,
    master_key: String,
    global_book_name: String,
    allow_registration: bool,
    session_lifetime_seconds: i64,
}

impl Config {
    fn from_env() -> Result<Self> {
        let bind = env_value("RUSTDESK_ACCOUNT_BIND", "0.0.0.0:21114")
            .parse()
            .context("RUSTDESK_ACCOUNT_BIND is invalid")?;
        let session_days: i64 = env_value("RUSTDESK_ACCOUNT_SESSION_DAYS", "30")
            .parse()
            .context("RUSTDESK_ACCOUNT_SESSION_DAYS is invalid")?;
        if !(1..=365).contains(&session_days) {
            anyhow::bail!("RUSTDESK_ACCOUNT_SESSION_DAYS must be between 1 and 365");
        }
        let master_key = env::var("RUSTDESK_ACCOUNT_MASTER_KEY")
            .context("RUSTDESK_ACCOUNT_MASTER_KEY is required")?;
        Ok(Self {
            bind,
            database_path: env_value(
                "RUSTDESK_ACCOUNT_DB",
                "/var/lib/rustdesk-account/account.sqlite3",
            )
            .into(),
            tls_cert: env_value(
                "RUSTDESK_ACCOUNT_TLS_CERT",
                "/opt/rustdesk-selfhost/tls/server.crt",
            )
            .into(),
            tls_key: env_value(
                "RUSTDESK_ACCOUNT_TLS_KEY",
                "/opt/rustdesk-selfhost/tls/server.key",
            )
            .into(),
            master_key,
            global_book_name: env_value("RUSTDESK_ACCOUNT_GLOBAL_BOOK_NAME", "Shared devices"),
            allow_registration: parse_bool(&env_value(
                "RUSTDESK_ACCOUNT_ALLOW_REGISTRATION",
                "true",
            ))?,
            session_lifetime_seconds: session_days * 24 * 60 * 60,
        })
    }
}

fn env_value(name: &str, default: &str) -> String {
    env::var(name).unwrap_or_else(|_| default.to_owned())
}

fn parse_bool(value: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "on" => Ok(true),
        "0" | "false" | "no" | "off" => Ok(false),
        _ => anyhow::bail!("invalid boolean value: {value}"),
    }
}

pub fn unix_time() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn app(state: AppState) -> Router {
    Router::new()
        .route("/health", get(handlers::health))
        .route("/api/login-options", get(handlers::login_options))
        .route("/api/register", post(handlers::register))
        .route("/api/login", post(handlers::login))
        .route("/api/currentUser", post(handlers::current_user))
        .route("/api/logout", post(handlers::logout))
        .route("/api/ab/settings", post(handlers::ab_settings))
        .route("/api/ab/personal", post(handlers::personal_ab))
        .route("/api/ab/shared/profiles", post(handlers::shared_profiles))
        .route("/api/ab/peers", post(handlers::list_peers))
        .route("/api/ab/tags/{guid}", post(handlers::list_tags))
        .route("/api/ab/peer/add/{guid}", post(handlers::add_peer))
        .route("/api/ab/peer/update/{guid}", put(handlers::update_peer))
        .route("/api/ab/peer/{guid}", delete(handlers::delete_peers))
        .route("/api/ab/tag/add/{guid}", post(handlers::add_tag))
        .route("/api/ab/tag/update/{guid}", put(handlers::update_tag))
        .route("/api/ab/tag/rename/{guid}", put(handlers::rename_tag))
        .route("/api/ab/tag/{guid}", delete(handlers::delete_tags))
        .with_state(state)
}

async fn shutdown_signal(handle: Handle) {
    let interrupt = async {
        if let Err(error) = tokio::signal::ctrl_c().await {
            tracing::error!(%error, "failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => tracing::error!(%error, "failed to install SIGTERM handler"),
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = interrupt => {},
        _ = terminate => {},
    }
    handle.graceful_shutdown(Some(Duration::from_secs(10)));
}

fn require_file(path: &Path) -> Result<()> {
    if !path.is_file() {
        anyhow::bail!("required file does not exist: {}", path.display());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()))
        .init();

    let config = Config::from_env()?;
    require_file(&config.tls_cert)?;
    require_file(&config.tls_key)?;
    let database = Arc::new(Database::open(
        &config.database_path,
        &config.global_book_name,
    )?);
    let state = AppState {
        database,
        crypto: Arc::new(Crypto::new(&config.master_key)?),
        allow_registration: config.allow_registration,
        session_lifetime_seconds: config.session_lifetime_seconds,
    };
    let tls = RustlsConfig::from_pem_file(&config.tls_cert, &config.tls_key)
        .await
        .context("failed to load TLS certificate")?;
    let handle = Handle::new();
    tokio::spawn(shutdown_signal(handle.clone()));
    tracing::info!(bind = %config.bind, "RustDesk account server starting");
    axum_server::bind_rustls(config.bind, tls)
        .handle(handle)
        .serve(app(state).into_make_service())
        .await
        .context("account server stopped unexpectedly")
}
