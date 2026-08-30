use serde::{Deserialize, Serialize};

#[derive(Debug, Clone)]
pub struct User {
    pub id: i64,
    pub username: String,
    pub display_name: String,
}

#[derive(Debug, Deserialize)]
pub struct RegisterRequest {
    pub username: String,
    pub password: String,
    #[serde(default)]
    pub display_name: String,
}

#[derive(Debug, Deserialize)]
pub struct LoginRequest {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Deserialize)]
pub struct DeviceUpsertRequest {
    pub id: String,
    pub alias: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct UserPayload {
    pub name: String,
    pub display_name: String,
    pub avatar: String,
    pub email: String,
    pub note: String,
    pub status: i32,
    pub is_admin: bool,
}

impl From<&User> for UserPayload {
    fn from(user: &User) -> Self {
        Self {
            name: user.username.clone(),
            display_name: user.display_name.clone(),
            avatar: String::new(),
            email: String::new(),
            note: String::new(),
            status: 1,
            is_admin: false,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct LoginResponse {
    pub access_token: String,
    pub r#type: &'static str,
    pub user: UserPayload,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PageQuery {
    #[serde(default = "default_page")]
    pub current: u32,
    #[serde(default = "default_page_size")]
    pub page_size: u32,
    #[serde(default)]
    pub ab: String,
}

fn default_page() -> u32 {
    1
}

fn default_page_size() -> u32 {
    100
}

impl PageQuery {
    pub fn limit_and_offset(&self) -> (i64, i64) {
        let limit = self.page_size.clamp(1, 500) as i64;
        let page = self.current.max(1) as i64;
        (limit, (page - 1) * limit)
    }
}

#[derive(Debug, Serialize)]
pub struct Page<T> {
    pub total: i64,
    pub data: Vec<T>,
}

#[derive(Debug, Serialize)]
pub struct AddressBookProfile {
    pub guid: String,
    pub name: String,
    pub owner: String,
    pub note: String,
    pub rule: i32,
    pub info: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PeerPayload {
    pub id: String,
    #[serde(default)]
    pub hash: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub platform: String,
    #[serde(default)]
    pub alias: String,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub note: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_server: Option<bool>,
}

#[derive(Debug, Deserialize)]
pub struct PeerUpdate {
    pub id: String,
    pub hash: Option<String>,
    pub password: Option<String>,
    pub username: Option<String>,
    pub hostname: Option<String>,
    pub platform: Option<String>,
    pub alias: Option<String>,
    pub tags: Option<Vec<String>>,
    pub note: Option<String>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct TagPayload {
    pub name: String,
    pub color: i64,
}

#[derive(Debug, Deserialize)]
pub struct RenameTagRequest {
    pub old: String,
    pub new: String,
}
