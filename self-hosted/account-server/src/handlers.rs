use axum::{
    extract::{Path, Query, State},
    http::{header::AUTHORIZATION, HeaderMap, StatusCode},
    Json,
};
use serde_json::{json, Value};

use crate::{
    crypto::{hash_password, new_session_token, token_hash, verify_password},
    db::BookKind,
    error::{ApiError, ApiResult},
    model::{
        DeviceUpsertRequest, LoginRequest, LoginResponse, Page, PageQuery, PeerPayload, PeerUpdate,
        RegisterRequest, RenameTagRequest, TagPayload, User, UserPayload,
    },
    unix_time, AppState,
};

const DEFAULT_DEVICE_PASSWORD: &str = "Zdrive-2026";
const DEVICE_SHARE_TOKEN_HEADER: &str = "x-device-share-token";

fn device_alias(requested: &str, username: Option<&str>, hostname: &str, peer_id: &str) -> String {
    let requested = requested.trim();
    if !requested.is_empty() {
        return requested.to_owned();
    }
    if let Some(username) = username.map(str::trim).filter(|value| !value.is_empty()) {
        return username.to_owned();
    }
    let hostname = hostname.trim();
    if !hostname.is_empty() {
        return hostname.to_owned();
    }
    peer_id.to_owned()
}

fn device_password(requested: Option<&str>) -> &str {
    requested
        .filter(|value| !value.is_empty())
        .unwrap_or(DEFAULT_DEVICE_PASSWORD)
}

fn internal(error: impl std::fmt::Display) -> ApiError {
    ApiError::internal(error)
}

fn bearer_token(headers: &HeaderMap) -> ApiResult<&str> {
    let value = headers
        .get(AUTHORIZATION)
        .ok_or_else(|| ApiError::unauthorized("Missing bearer token"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Invalid authorization header"))?;
    value
        .strip_prefix("Bearer ")
        .filter(|token| !token.is_empty())
        .ok_or_else(|| ApiError::unauthorized("Invalid bearer token"))
}

fn authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<(User, String)> {
    let token = bearer_token(headers)?;
    let user = state
        .database
        .user_by_token(token)
        .map_err(internal)?
        .ok_or_else(|| ApiError::unauthorized("Session expired or invalid"))?;
    Ok((user, token.to_owned()))
}

fn optional_authenticated(state: &AppState, headers: &HeaderMap) -> ApiResult<Option<User>> {
    if headers.get(AUTHORIZATION).is_none() {
        return Ok(None);
    }
    authenticated(state, headers).map(|(user, _)| Some(user))
}

fn validate_device_share_token(token: &str) -> ApiResult<()> {
    if !(32..=256).contains(&token.len()) || token.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Invalid device share token"));
    }
    Ok(())
}

fn device_share_token(headers: &HeaderMap) -> ApiResult<&str> {
    let token = headers
        .get(DEVICE_SHARE_TOKEN_HEADER)
        .ok_or_else(|| ApiError::unauthorized("Missing device share token"))?
        .to_str()
        .map_err(|_| ApiError::unauthorized("Invalid device share token"))?;
    validate_device_share_token(token)?;
    Ok(token)
}

fn validate_username(username: &str) -> ApiResult<()> {
    if !(3..=64).contains(&username.len()) {
        return Err(ApiError::bad_request(
            "Username must contain between 3 and 64 characters",
        ));
    }
    if !username
        .chars()
        .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(ApiError::bad_request(
            "Username may only contain letters, numbers, dot, underscore, and hyphen",
        ));
    }
    Ok(())
}

fn validate_password(password: &str) -> ApiResult<()> {
    if password.len() < 8 || password.len() > 256 {
        return Err(ApiError::bad_request(
            "Password must contain between 8 and 256 characters",
        ));
    }
    Ok(())
}

fn validate_peer_id(peer_id: &str) -> ApiResult<()> {
    if peer_id.is_empty() || peer_id.len() > 64 || peer_id.chars().any(char::is_control) {
        return Err(ApiError::bad_request("Invalid RustDesk ID"));
    }
    Ok(())
}

fn issue_session(state: &AppState, user: &User) -> ApiResult<LoginResponse> {
    let token = new_session_token();
    let expires_at = unix_time() + state.session_lifetime_seconds;
    state
        .database
        .create_session(user.id, &token, expires_at)
        .map_err(internal)?;
    Ok(LoginResponse {
        access_token: token,
        r#type: "access_token",
        user: UserPayload::from(user),
    })
}

async fn require_book(
    state: &AppState,
    headers: &HeaderMap,
    guid: &str,
) -> ApiResult<(User, BookKind)> {
    let (user, _) = authenticated(state, headers)?;
    let kind = state
        .database
        .book_kind_for_user(guid, user.id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::forbidden("Address book is not accessible"))?;
    Ok((user, kind))
}

pub async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

pub async fn login_options() -> Json<Vec<String>> {
    Json(Vec::new())
}

pub async fn register(
    State(state): State<AppState>,
    Json(request): Json<RegisterRequest>,
) -> ApiResult<Json<LoginResponse>> {
    if !state.allow_registration {
        return Err(ApiError::forbidden("Registration is disabled"));
    }
    let username = request.username.trim();
    let display_name = request.display_name.trim();
    validate_username(username)?;
    validate_password(&request.password)?;
    if display_name.len() > 128 {
        return Err(ApiError::bad_request("Display name is too long"));
    }
    if state.database.user_exists(username).map_err(internal)? {
        return Err(ApiError::conflict("Username already exists"));
    }
    let password_hash = hash_password(&request.password).map_err(internal)?;
    let user = state
        .database
        .create_user(username, display_name, &password_hash)
        .map_err(internal)?;
    Ok(Json(issue_session(&state, &user)?))
}

pub async fn login(
    State(state): State<AppState>,
    Json(request): Json<LoginRequest>,
) -> ApiResult<Json<LoginResponse>> {
    let username = request.username.trim();
    let Some((user, password_hash)) = state.database.login_record(username).map_err(internal)?
    else {
        return Err(ApiError::unauthorized("Invalid username or password"));
    };
    if !verify_password(&request.password, &password_hash) {
        return Err(ApiError::unauthorized("Invalid username or password"));
    }
    Ok(Json(issue_session(&state, &user)?))
}

pub async fn current_user(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<UserPayload>> {
    let (user, _) = authenticated(&state, &headers)?;
    Ok(Json(UserPayload::from(&user)))
}

pub async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<StatusCode> {
    let (_, token) = authenticated(&state, &headers)?;
    state.database.delete_session(&token).map_err(internal)?;
    Ok(StatusCode::OK)
}

pub async fn upsert_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<DeviceUpsertRequest>,
) -> ApiResult<StatusCode> {
    let user = optional_authenticated(&state, &headers)?;
    validate_peer_id(&request.id)?;
    validate_device_share_token(&request.share_token)?;
    let alias = device_alias(
        &request.alias,
        user.as_ref().map(|user| user.username.as_str()),
        &request.hostname,
        &request.id,
    );
    if alias.len() > 128 || alias.chars().any(char::is_control) {
        return Err(ApiError::bad_request(
            "Device alias must not exceed 128 characters or contain control characters",
        ));
    }
    if request.hostname.len() > 255 || request.platform.len() > 128 || request.username.len() > 128
    {
        return Err(ApiError::bad_request("Device metadata is too long"));
    }
    if request
        .password
        .as_ref()
        .is_some_and(|value| value.len() > 256)
    {
        return Err(ApiError::bad_request("Device password is too long"));
    }

    let password = device_password(request.password.as_deref()).to_owned();
    let peer_username = user
        .as_ref()
        .map(|user| user.username.clone())
        .unwrap_or_else(|| request.username.trim().to_owned());
    let device_token_hash = token_hash(&request.share_token);
    let peer = PeerPayload {
        id: request.id.clone(),
        hash: String::new(),
        password: password.clone(),
        username: peer_username,
        hostname: request.hostname,
        platform: request.platform,
        alias,
        tags: Vec::new(),
        note: String::new(),
        same_server: Some(true),
    };
    if let Some(stored_device_token_hash) = state
        .database
        .peer_device_token_hash(crate::db::GLOBAL_BOOK_GUID, &request.id)
        .map_err(internal)?
    {
        if !stored_device_token_hash.is_empty() && stored_device_token_hash != device_token_hash {
            return Err(ApiError::unauthorized("Device share token does not match"));
        }
        state
            .database
            .update_peer(
                crate::db::GLOBAL_BOOK_GUID,
                PeerUpdate {
                    id: request.id.clone(),
                    hash: None,
                    password: Some(password),
                    username: Some(peer.username),
                    hostname: Some(peer.hostname),
                    platform: Some(peer.platform),
                    alias: Some(peer.alias),
                    tags: None,
                    note: None,
                },
                &state.crypto,
            )
            .map_err(internal)?;
        if stored_device_token_hash.is_empty() {
            state
                .database
                .set_peer_device_token_hash(
                    crate::db::GLOBAL_BOOK_GUID,
                    &request.id,
                    &device_token_hash,
                )
                .map_err(internal)?;
        }
    } else {
        let owner_user_id = match user {
            Some(user) => user.id,
            None => state.database.system_device_owner_id().map_err(internal)?,
        };
        state
            .database
            .add_peer(
                crate::db::GLOBAL_BOOK_GUID,
                owner_user_id,
                &peer,
                &peer.password,
                &device_token_hash,
                &state.crypto,
            )
            .map_err(internal)?;
    }
    Ok(StatusCode::OK)
}

pub async fn unshare_device(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> ApiResult<StatusCode> {
    validate_peer_id(&id)?;
    let requested_device_token_hash = token_hash(device_share_token(&headers)?);
    let Some(stored_device_token_hash) = state
        .database
        .peer_device_token_hash(crate::db::GLOBAL_BOOK_GUID, &id)
        .map_err(internal)?
    else {
        return Ok(StatusCode::NO_CONTENT);
    };
    if stored_device_token_hash.is_empty()
        || stored_device_token_hash != requested_device_token_hash
    {
        return Err(ApiError::unauthorized("Device share token does not match"));
    }
    state
        .database
        .delete_peers(crate::db::GLOBAL_BOOK_GUID, &[id])
        .map_err(internal)?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn ab_settings(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    authenticated(&state, &headers)?;
    Ok(Json(json!({ "max_peer_one_ab": 0 })))
}

pub async fn personal_ab(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> ApiResult<Json<Value>> {
    let (user, _) = authenticated(&state, &headers)?;
    let guid = state
        .database
        .personal_guid(user.id)
        .map_err(internal)?
        .ok_or_else(|| ApiError::internal("personal address book is missing"))?;
    Ok(Json(json!({ "guid": guid })))
}

pub async fn shared_profiles(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<Page<crate::model::AddressBookProfile>>> {
    authenticated(&state, &headers)?;
    let profile = state.database.global_profile().map_err(internal)?;
    let include = query.current <= 1;
    Ok(Json(Page {
        total: 1,
        data: if include { vec![profile] } else { Vec::new() },
    }))
}

pub async fn list_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<PageQuery>,
) -> ApiResult<Json<Page<PeerPayload>>> {
    if query.ab.is_empty() {
        return Err(ApiError::bad_request("Missing address book"));
    }
    require_book(&state, &headers, &query.ab).await?;
    let (limit, offset) = query.limit_and_offset();
    Ok(Json(
        state
            .database
            .list_peers(&query.ab, limit, offset, &state.crypto)
            .map_err(internal)?,
    ))
}

pub async fn add_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(mut peer): Json<PeerPayload>,
) -> ApiResult<StatusCode> {
    let (user, kind) = require_book(&state, &headers, &guid).await?;
    validate_peer_id(&peer.id)?;
    if state
        .database
        .peer_exists(&guid, &peer.id)
        .map_err(internal)?
    {
        return Err(ApiError::conflict("RustDesk ID already exists"));
    }
    let password = if kind == BookKind::Global {
        peer.password.clone()
    } else {
        peer.password.clear();
        String::new()
    };
    state
        .database
        .add_peer(&guid, user.id, &peer, &password, "", &state.crypto)
        .map_err(internal)?;
    Ok(StatusCode::OK)
}

pub async fn update_peer(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(mut update): Json<PeerUpdate>,
) -> ApiResult<StatusCode> {
    let (_, kind) = require_book(&state, &headers, &guid).await?;
    validate_peer_id(&update.id)?;
    if kind == BookKind::Personal {
        update.password = None;
    } else {
        update.hash = None;
    }
    if !state
        .database
        .update_peer(&guid, update, &state.crypto)
        .map_err(internal)?
    {
        return Err(ApiError::not_found("RustDesk ID was not found"));
    }
    Ok(StatusCode::OK)
}

pub async fn delete_peers(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(peer_ids): Json<Vec<String>>,
) -> ApiResult<StatusCode> {
    require_book(&state, &headers, &guid).await?;
    state
        .database
        .delete_peers(&guid, &peer_ids)
        .map_err(internal)?;
    Ok(StatusCode::OK)
}

pub async fn list_tags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
) -> ApiResult<Json<Vec<TagPayload>>> {
    require_book(&state, &headers, &guid).await?;
    Ok(Json(state.database.list_tags(&guid).map_err(internal)?))
}

pub async fn add_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(tag): Json<TagPayload>,
) -> ApiResult<StatusCode> {
    require_book(&state, &headers, &guid).await?;
    if tag.name.trim().is_empty() || tag.name.len() > 64 {
        return Err(ApiError::bad_request("Invalid tag name"));
    }
    state.database.add_tag(&guid, &tag).map_err(internal)?;
    Ok(StatusCode::OK)
}

pub async fn update_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(tag): Json<TagPayload>,
) -> ApiResult<StatusCode> {
    require_book(&state, &headers, &guid).await?;
    if !state.database.update_tag(&guid, &tag).map_err(internal)? {
        return Err(ApiError::not_found("Tag was not found"));
    }
    Ok(StatusCode::OK)
}

pub async fn rename_tag(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(request): Json<RenameTagRequest>,
) -> ApiResult<StatusCode> {
    require_book(&state, &headers, &guid).await?;
    if request.new.trim().is_empty() || request.new.len() > 64 {
        return Err(ApiError::bad_request("Invalid tag name"));
    }
    if !state
        .database
        .rename_tag(&guid, &request.old, &request.new)
        .map_err(internal)?
    {
        return Err(ApiError::not_found("Tag was not found"));
    }
    Ok(StatusCode::OK)
}

pub async fn delete_tags(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(guid): Path<String>,
    Json(names): Json<Vec<String>>,
) -> ApiResult<StatusCode> {
    require_book(&state, &headers, &guid).await?;
    state
        .database
        .delete_tags(&guid, &names)
        .map_err(internal)?;
    Ok(StatusCode::OK)
}

#[cfg(test)]
mod tests {
    use super::{
        device_alias, device_password, validate_device_share_token, DEFAULT_DEVICE_PASSWORD,
    };

    #[test]
    fn device_alias_uses_requested_name_then_account_then_hostname() {
        assert_eq!(
            device_alias(" Workstation ", Some("alice"), "host-a", "123"),
            "Workstation"
        );
        assert_eq!(device_alias("   ", Some("alice"), "host-a", "123"), "alice");
        assert_eq!(device_alias("", None, "host-a", "123"), "host-a");
        assert_eq!(device_alias("", None, "", "123"), "123");
    }

    #[test]
    fn blank_device_password_uses_private_default() {
        assert_eq!(device_password(None), DEFAULT_DEVICE_PASSWORD);
        assert_eq!(device_password(Some("")), DEFAULT_DEVICE_PASSWORD);
        assert_eq!(device_password(Some("custom")), "custom");
    }

    #[test]
    fn device_share_token_requires_sufficient_entropy() {
        assert!(validate_device_share_token(&"a".repeat(32)).is_ok());
        assert!(validate_device_share_token("short").is_err());
        assert!(validate_device_share_token(&format!("{}\n", "a".repeat(32))).is_err());
    }
}
