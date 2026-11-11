//! Local accounts (Argon2id) + short-lived JWT + role check layer.
//! Roles: viewer < analyst < policy_author < enforcer < admin.

use crate::App;
use argon2::{
    password_hash::{rand_core::OsRng, PasswordHash, PasswordHasher, PasswordVerifier, SaltString},
    Argon2,
};
use axum::{
    extract::{Request, State},
    http::{header, StatusCode},
    middleware::Next,
    response::Response,
    Json,
};
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

pub const ROLES: &[&str] = &["viewer", "analyst", "policy_author", "enforcer", "admin"];

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Claims {
    pub sub: String,
    pub role: String,
    pub exp: usize,
}

#[derive(Deserialize)]
pub struct Login {
    pub username: String,
    pub password: String,
}
#[derive(Serialize)]
pub struct Token {
    pub token: String,
    pub role: String,
    pub expires_in: u64,
}

pub async fn login(
    State(app): State<App>,
    Json(l): Json<Login>,
) -> Result<Json<Token>, StatusCode> {
    let row: Option<(String, String, bool)> =
        sqlx::query_as("SELECT password_hash, role, enabled FROM users WHERE username=$1")
            .bind(&l.username)
            .fetch_optional(&app.pg)
            .await
            .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let Some((hash, role, enabled)) = row else {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        return Err(StatusCode::UNAUTHORIZED);
    };
    let parsed = PasswordHash::new(&hash).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    if !enabled
        || Argon2::default()
            .verify_password(l.password.as_bytes(), &parsed)
            .is_err()
    {
        audit(&app, &l.username, "login.failed", "").await;
        return Err(StatusCode::UNAUTHORIZED);
    }
    let exp = (chrono::Utc::now() + chrono::Duration::hours(8)).timestamp() as usize;
    let token = encode(
        &Header::default(),
        &Claims {
            sub: l.username.clone(),
            role: role.clone(),
            exp,
        },
        &EncodingKey::from_secret(app.jwt_secret.as_bytes()),
    )
    .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    audit(&app, &l.username, "login.ok", "").await;
    Ok(Json(Token {
        token,
        role,
        expires_in: 8 * 3600,
    }))
}

pub async fn me(claims: axum::Extension<Claims>) -> Json<Claims> {
    Json(claims.0)
}

pub async fn jwt_middleware(
    State(app): State<App>,
    mut req: Request,
    next: Next,
) -> Result<Response, StatusCode> {
    if req.uri().path().ends_with("/auth/login") {
        return Ok(next.run(req).await);
    }
    let tok = req
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .or_else(|| {
            req.uri()
                .query()
                .and_then(|q| q.split('&').find_map(|kv| kv.strip_prefix("token=")))
        })
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let data = decode::<Claims>(
        tok,
        &DecodingKey::from_secret(app.jwt_secret.as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| StatusCode::UNAUTHORIZED)?;
    req.extensions_mut().insert(data.claims);
    Ok(next.run(req).await)
}

/// Role gates. Use as `axum::middleware::from_fn(auth::require_enforcer)`.
async fn require_role(
    req: Request,
    next: Next,
    min_role: &'static str,
) -> Result<Response, StatusCode> {
    let claims = req
        .extensions()
        .get::<Claims>()
        .ok_or(StatusCode::UNAUTHORIZED)?;
    let have = ROLES.iter().position(|r| *r == claims.role).unwrap_or(0);
    let need = ROLES
        .iter()
        .position(|r| *r == min_role)
        .unwrap_or(usize::MAX);
    if have < need {
        return Err(StatusCode::FORBIDDEN);
    }
    Ok(next.run(req).await)
}
pub async fn require_analyst(req: Request, next: Next) -> Result<Response, StatusCode> {
    require_role(req, next, "analyst").await
}
pub async fn require_policy_author(req: Request, next: Next) -> Result<Response, StatusCode> {
    require_role(req, next, "policy_author").await
}
pub async fn require_enforcer(req: Request, next: Next) -> Result<Response, StatusCode> {
    require_role(req, next, "enforcer").await
}
pub async fn require_admin(req: Request, next: Next) -> Result<Response, StatusCode> {
    require_role(req, next, "admin").await
}

pub async fn audit(app: &App, actor: &str, action: &str, detail: &str) {
    let _ = sqlx::query("INSERT INTO audit_log(actor, action, detail, ts) VALUES($1,$2,$3,now())")
        .bind(actor)
        .bind(action)
        .bind(detail)
        .execute(&app.pg)
        .await;
}

pub fn hash_password(pw: &str) -> String {
    let salt = SaltString::generate(&mut OsRng);
    Argon2::default()
        .hash_password(pw.as_bytes(), &salt)
        .expect("argon2")
        .to_string()
}

/// On first start create `admin` with a random password printed once to the log.
pub async fn ensure_bootstrap_admin(app: &App) -> anyhow::Result<()> {
    let n: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM users")
        .fetch_one(&app.pg)
        .await?;
    if n.0 == 0 {
        let pw = std::env::var("HV_ADMIN_PASSWORD")
            .unwrap_or_else(|_| uuid::Uuid::new_v4().simple().to_string());
        sqlx::query("INSERT INTO users(username, password_hash, role, enabled) VALUES('admin',$1,'admin',true)").bind(hash_password(&pw)).execute(&app.pg).await?;
        tracing::warn!(username = "admin", password = %pw, "bootstrap admin created; change this password now");
    }
    Ok(())
}
