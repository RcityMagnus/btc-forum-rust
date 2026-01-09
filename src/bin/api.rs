use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, Query, State},
    http::{HeaderMap, HeaderValue, Method, Request, StatusCode, header::HeaderName},
    middleware::Next,
    response::{Html, IntoResponse, Response},
    routing::{get, post},
};
use argon2::{
    Argon2,
    password_hash::{PasswordHash, PasswordVerifier},
};
use chrono::Utc;
use dotenvy::dotenv;
use jsonwebtoken::{EncodingKey, Header, encode};
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json::json;
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tower_http::trace::TraceLayer;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use btc_forum_rust::{
    auth::AuthClaims,
    services::{ForumContext, ForumService, SendPersonalMessage, surreal::SurrealService},
    subs_auth::hash_password,
    surreal::{SurrealForumService, SurrealPost, SurrealTopic, SurrealUser, connect_from_env},
};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct AppState {
    surreal: SurrealForumService,
    forum_service: SurrealService,
    rate_limiter: Arc<RateLimiter>,
    start_time: Instant,
}

#[derive(Default)]
struct RateLimiter {
    // key -> (count, window_start)
    limits: std::sync::Mutex<std::collections::HashMap<String, (u32, Instant)>>,
}

impl RateLimiter {
    fn new() -> Self {
        Self {
            limits: std::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    fn allow(&self, key: &str, max: u32, window: Duration) -> bool {
        let mut guard = match self.limits.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        let now = Instant::now();
        let entry = guard.entry(key.to_string()).or_insert((0, now));
        let elapsed = now.duration_since(entry.1);
        if elapsed >= window {
            *entry = (1, now);
            true
        } else if entry.0 < max {
            entry.0 += 1;
            true
        } else {
            false
        }
    }

    fn snapshot(&self) -> std::collections::HashMap<String, u32> {
        let guard = match self.limits.lock() {
            Ok(g) => g,
            Err(poison) => poison.into_inner(),
        };
        guard
            .iter()
            .map(|(k, (count, _))| (k.clone(), *count))
            .collect()
    }
}

#[derive(Deserialize)]
struct RegisterRequest {
    username: String,
    password: String,
    role: Option<String>,
    permissions: Option<Vec<String>>,
}

#[derive(Deserialize)]
struct LoginRequest {
    username: String,
    password: String,
}

static ENFORCE_CSRF: OnceLock<bool> = OnceLock::new();

fn csrf_enabled() -> bool {
    *ENFORCE_CSRF.get_or_init(|| {
        env::var("ENFORCE_CSRF")
            .map(|v| !matches!(v.to_lowercase().as_str(), "0" | "false" | "off"))
            .unwrap_or(true)
    })
}

fn require_auth(claims: &Option<AuthClaims>) -> Result<&AuthClaims, impl IntoResponse> {
    if let Some(claims) = claims {
        Ok(claims)
    } else {
        Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "authorization required"})),
        ))
    }
}

fn jwt_ttl_secs() -> i64 {
    env::var("JWT_TTL_SECS")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(3600)
}

fn issue_token_for_user(
    user: &SurrealUser,
) -> Result<String, (StatusCode, Json<serde_json::Value>)> {
    let now = Utc::now().timestamp();
    let claims = AuthClaims {
        sub: user.name.clone(),
        exp: now + jwt_ttl_secs(),
        iat: now,
        role: user.role.clone(),
        permissions: user.permissions.clone(),
        session_id: None,
    };
    let secret = env::var("JWT_SECRET").map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "message": "server jwt secret not configured"})),
        )
    })?;
    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
    .map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "message": "failed to sign token"})),
        )
    })
}

fn build_ctx_from_user(user: &SurrealUser, claims: &AuthClaims) -> ForumContext {
    let mut ctx = ForumContext::default();
    ctx.user_info.is_guest = false;
    ctx.user_info.name = user.name.clone();

    if let Some(role) = user.role.as_deref().or_else(|| claims.role.as_deref()) {
        match role {
            "admin" => ctx.user_info.is_admin = true,
            "mod" => ctx.user_info.is_mod = true,
            _ => {}
        }
    }

    if let Some(perms) = user
        .permissions
        .clone()
        .or_else(|| claims.permissions.clone())
    {
        ctx.user_info.permissions.extend(perms);
    }

    if ctx.user_info.permissions.is_empty() && !ctx.user_info.is_admin && !ctx.user_info.is_mod {
        ctx.user_info.permissions.insert("post_new".into());
        ctx.user_info.permissions.insert("post_reply_any".into());
    }

    ctx
}

fn verify_password_hash(password: &str, stored: Option<&str>) -> bool {
    let Some(stored) = stored else {
        return false;
    };
    if stored.is_empty() {
        return false;
    }
    if stored.starts_with("$argon2") {
        if let Ok(parsed) = PasswordHash::new(stored) {
            return Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok();
        }
    }
    password == stored
}

async fn ensure_user_ctx(
    state: &AppState,
    claims: &AuthClaims,
) -> Result<(SurrealUser, ForumContext), (StatusCode, Json<serde_json::Value>)> {
    match state
        .surreal
        .ensure_user(
            &claims.sub,
            claims.role.as_deref(),
            claims.permissions.as_deref(),
        )
        .await
    {
        Ok(user) => {
            let ctx = build_ctx_from_user(&user, claims);
            Ok((user, ctx))
        }
        Err(err) => {
            error!(error = %err, "failed to ensure user");
            Err((
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "failed to ensure user"})),
            ))
        }
    }
}

fn ensure_permission(
    state: &AppState,
    ctx: &ForumContext,
    permission: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.forum_service.allowed_to(ctx, permission, None, false) {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({
                "status": "error",
                "message": format!("missing permission: {permission}")
            })),
        ))
    }
}

fn ensure_admin(ctx: &ForumContext) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if ctx.user_info.is_admin || ctx.user_info.permissions.contains("admin") {
        Ok(())
    } else {
        Err((
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "admin permission required"})),
        ))
    }
}

fn enforce_rate(
    state: &AppState,
    key: &str,
    limit: u32,
    window: Duration,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    if state.rate_limiter.allow(key, limit, window) {
        Ok(())
    } else {
        Err((
            StatusCode::TOO_MANY_REQUESTS,
            Json(json!({
                "status": "error",
                "message": "rate limit exceeded"
            })),
        ))
    }
}

fn rate_key(claims: &AuthClaims, addr: Option<&std::net::SocketAddr>) -> String {
    if let Some(ip) = addr {
        format!("{}:{}", claims.sub, ip.ip())
    } else {
        claims.sub.clone()
    }
}

fn generate_csrf_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn find_csrf_cookie(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie| {
            cookie
                .split(';')
                .find_map(|part| part.trim().strip_prefix("XSRF-TOKEN="))
                .map(|v| v.to_string())
        })
}

fn verify_csrf(headers: &HeaderMap) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    // Simple double-submit style check: X-CSRF-TOKEN must equal Cookie XSRF-TOKEN.
    let header_token = headers
        .get("x-csrf-token")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default();
    if header_token.is_empty() {
        return Err((
            StatusCode::FORBIDDEN,
            Json(json!({"status": "error", "message": "missing csrf token"})),
        ));
    }
    if let (Some(header_token), Some(cookie_header)) = (
        headers.get("x-csrf-token"),
        headers.get(axum::http::header::COOKIE),
    ) {
        let header_val = header_token.to_str().unwrap_or_default();
        let cookie_val = cookie_header.to_str().unwrap_or_default();
        let mut ok = false;
        for part in cookie_val.split(';') {
            let trimmed = part.trim();
            if let Some(rest) = trimmed.strip_prefix("XSRF-TOKEN=") {
                if rest == header_val {
                    ok = true;
                    break;
                }
            }
        }
        if !ok {
            return Err((
                StatusCode::FORBIDDEN,
                Json(json!({"status": "error", "message": "csrf token mismatch"})),
            ));
        }
    }
    Ok(())
}
fn validate_content(
    subject: &str,
    body: &str,
) -> Result<(), (StatusCode, Json<serde_json::Value>)> {
    let s = subject.trim();
    let b = body.trim();
    if s.is_empty() || s.len() > 200 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "subject must be 1..200 chars"})),
        ));
    }
    if b.is_empty() || b.len() > 10_000 {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "body must be 1..10000 chars"})),
        ));
    }
    Ok(())
}

async fn csrf_layer(mut req: Request<Body>, next: Next) -> Response {
    let csrf_on = csrf_enabled();
    let method = req.method().clone();
    let path = req.uri().path().to_string();
    let mut set_cookie: Option<String> = None;

    if csrf_on {
        // Issue a token cookie for safe methods to reduce friction on first load.
        if matches!(method, Method::GET | Method::OPTIONS) && find_csrf_cookie(req.headers()).is_none()
        {
            set_cookie = Some(generate_csrf_token());
        }

        if !matches!(method, Method::GET | Method::OPTIONS) && !path.starts_with("/auth/") {
            let headers = req.headers().clone();
            if let Err(err) = verify_csrf(&headers) {
                return err.into_response();
            }
            req.extensions_mut().insert(headers);
        }
    }

    let mut response = next.run(req).await;
    if let Some(token) = set_cookie {
        if let Ok(value) =
            HeaderValue::from_str(&format!("XSRF-TOKEN={}; Path=/; SameSite=Lax", token))
        {
            response
                .headers_mut()
                .append(axum::http::header::SET_COOKIE, value);
        }
    }
    response
}

fn sanitize_input(input: &str) -> String {
    ammonia::Builder::default()
        .url_schemes(["http", "https"].into())
        .clean(input)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, http::Request, middleware::from_fn, routing::post};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};
    use tower::ServiceExt;

    #[test]
    fn validate_content_ok() {
        assert!(validate_content("hello", "body").is_ok());
    }

    #[test]
    fn validate_content_empty_subject_err() {
        assert!(validate_content("", "body").is_err());
    }

    #[test]
    fn validate_content_empty_body_err() {
        assert!(validate_content("hello", " ").is_err());
    }

    #[test]
    fn require_auth_rejects_missing_claims() {
        let result = require_auth(&None);
        assert!(result.is_err());
    }

    #[test]
    fn csrf_mismatch_rejected() {
        let mut headers = HeaderMap::new();
        headers.insert("x-csrf-token", HeaderValue::from_static("abc"));
        headers.insert(
            axum::http::header::COOKIE,
            HeaderValue::from_static("XSRF-TOKEN=def"),
        );
        assert!(verify_csrf(&headers).is_err());
    }

    #[test]
    fn rate_limiter_hits_limit() {
        let limiter = RateLimiter::new();
        let key = "user1";
        assert!(limiter.allow(key, 2, Duration::from_secs(60)));
        assert!(limiter.allow(key, 2, Duration::from_secs(60)));
        assert!(!limiter.allow(key, 2, Duration::from_secs(60)));
    }

    #[test]
    fn rate_key_with_ip() {
        let claims = AuthClaims {
            sub: "alice".into(),
            exp: 0,
            iat: 0,
            session_id: None,
            role: None,
            permissions: None,
        };
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let key = rate_key(&claims, Some(&addr));
        assert!(key.contains("alice"));
        assert!(key.contains("127.0.0.1"));
    }

    #[tokio::test]
    async fn csrf_layer_blocks_missing_token() {
        let app = Router::new()
            .route("/test", post(|| async { StatusCode::OK }))
            .layer(from_fn(csrf_layer));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn csrf_layer_allows_with_token() {
        let app = Router::new()
            .route("/test", post(|| async { StatusCode::OK }))
            .layer(from_fn(csrf_layer));
        let req = Request::builder()
            .method(Method::POST)
            .uri("/test")
            .header("x-csrf-token", "abc")
            .header(axum::http::header::COOKIE, "XSRF-TOKEN=abc")
            .body(Body::empty())
            .unwrap();
        let response = app.oneshot(req).await.unwrap();
        assert_ne!(response.status(), StatusCode::FORBIDDEN);
    }
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    init_tracing();

    let surreal = connect_from_env()
        .await
        .expect("failed to connect to SurrealDB");
    let surreal = SurrealForumService::new(surreal);
    let forum_service = SurrealService::new(surreal.client().clone());
    let cors_origin =
        env::var("CORS_ORIGIN").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());
    let state = AppState {
        surreal,
        forum_service,
        rate_limiter: Arc::new(RateLimiter::new()),
        start_time: Instant::now(),
    };
    let app = Router::new()
        .route("/health", get(health))
        .route("/metrics", get(metrics))
        .route("/auth/register", post(register))
        .route("/auth/login", post(login))
        .route("/ui", get(ui))
        .route("/demo/post", post(demo_post))
        .route("/demo/surreal", post(demo_surreal))
        .route("/surreal/post", post(surreal_post))
        .route("/surreal/posts", get(surreal_posts))
        .route(
            "/surreal/boards",
            get(surreal_boards).post(create_surreal_board),
        )
        .route(
            "/surreal/topics",
            get(list_surreal_topics).post(create_surreal_topic),
        )
        .route(
            "/surreal/topic/posts",
            get(list_surreal_posts_for_topic).post(create_surreal_topic_post),
        )
        .route("/admin/users", get(list_users))
        .route("/admin/bans", get(list_bans))
        .route("/admin/action_logs", get(list_action_logs))
        .route("/admin/notify", post(admin_notify))
        .layer(axum::middleware::from_fn(csrf_layer))
        .layer({
            let origin = cors_origin
                .parse::<HeaderValue>()
                .expect("invalid CORS_ORIGIN");
            CorsLayer::new()
                .allow_origin(origin)
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    HeaderName::from_static("x-csrf-token"),
                ])
                .allow_credentials(true)
        })
        .layer(TraceLayer::new_for_http())
        .with_state(state);

    let addr: SocketAddr = env::var("BIND_ADDR")
        .unwrap_or_else(|_| "127.0.0.1:3000".into())
        .parse()
        .expect("invalid BIND_ADDR, expected host:port");
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .expect("failed to bind HTTP listener");
    info!("API listening on http://{addr}");

    let app = app.into_make_service_with_connect_info::<SocketAddr>();
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .expect("server crashed");
}

fn init_tracing() {
    let env_filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    tracing_subscriber::fmt().with_env_filter(env_filter).init();
}

async fn health(State(state): State<AppState>) -> impl IntoResponse {
    let surreal_status = match state.surreal.health().await {
        Ok(_) => json!({"status": "ok"}),
        Err(err) => {
            error!(error = %err, "surreal connectivity check failed");
            json!({"status": "error", "message": err.to_string()})
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "service": "ok (surreal-only)",
            "surreal": surreal_status,
            "timestamp": Utc::now()
        })),
    )
}

async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let uptime = state.start_time.elapsed().as_secs();
    let rates = state.rate_limiter.snapshot();
    (
        StatusCode::OK,
        Json(json!({
            "status": "ok",
            "uptime_secs": uptime,
            "rate_limiter_keys": rates,
        })),
    )
}

async fn register(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<RegisterRequest>,
) -> impl IntoResponse {
    let key = format!("register:{}", addr.ip());
    if let Err(resp) = enforce_rate(&state, &key, 5, Duration::from_secs(60)) {
        return resp;
    }
    let username = payload.username.trim();
    if username.len() < 3 || username.len() > 64 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "username must be 3-64 chars"})),
        );
    }
    if payload.password.len() < 6 || payload.password.len() > 128 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "password must be 6-128 chars"})),
        );
    }

    match state.surreal.user_by_name(username).await {
        Ok(Some(_)) => {
            return (
                StatusCode::CONFLICT,
                Json(json!({"status": "error", "message": "user already exists"})),
            );
        }
        Ok(None) => {}
        Err(err) => {
            error!(error = %err, "failed to query user");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "failed to query user"})),
            );
        }
    }

    let password_hash = match hash_password(&payload.password) {
        Ok(hash) => hash,
        Err(err) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": err.to_string()})),
            );
        }
    };
    let role = payload.role.as_deref();
    let perms_slice = payload.permissions.as_deref();
    let user = match state
        .surreal
        .create_user_with_password(username, role, perms_slice, Some(&password_hash))
        .await
    {
        Ok(user) => user,
        Err(err) => {
            error!(error = %err, "failed to create user");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "failed to create user"})),
            );
        }
    };

    match issue_token_for_user(&user) {
        Ok(token) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "ok",
                "token": token,
                "user": {
                    "name": user.name,
                    "role": user.role,
                    "permissions": user.permissions.unwrap_or_default(),
                }
            })),
        ),
        Err(resp) => resp,
    }
}

async fn login(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<LoginRequest>,
) -> impl IntoResponse {
    let key = format!("login:{}", addr.ip());
    if let Err(resp) = enforce_rate(&state, &key, 10, Duration::from_secs(60)) {
        return resp;
    }
    let username = payload.username.trim();
    if username.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "username required"})),
        );
    }
    let user = match state.surreal.user_by_name(username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            return (
                StatusCode::UNAUTHORIZED,
                Json(json!({"status": "error", "message": "user not found"})),
            );
        }
        Err(err) => {
            error!(error = %err, "failed to fetch user");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": "failed to fetch user"})),
            );
        }
    };
    if !verify_password_hash(&payload.password, user.password_hash.as_deref()) {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"status": "error", "message": "invalid credentials"})),
        );
    }

    match issue_token_for_user(&user) {
        Ok(token) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "token": token,
                "user": {
                    "name": user.name,
                    "role": user.role,
                    "permissions": user.permissions.unwrap_or_default(),
                }
            })),
        ),
        Err(resp) => resp,
    }
}

/// CSRF 占位：如需 CSRF 防护，可在前端携带 token（双提交或表单隐藏字段），
/// 后端通过中间件校验自定义 Header 与 Cookie 一致性，再放行路由。

async fn ui() -> Html<&'static str> {
    Html(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Forum Demo</title>
  <style>
    body { font-family: Arial, sans-serif; max-width: 720px; margin: 40px auto; line-height: 1.6; }
    label { display: block; margin-top: 12px; }
    textarea, input { width: 100%; padding: 8px; }
    button { margin-top: 12px; padding: 10px 16px; cursor: pointer; }
    pre { background: #f4f4f4; padding: 12px; border-radius: 6px; }
  </style>
</head>
<body>
  <h1>Forum Demo</h1>
  <p>Paste a JWT (from Rainbow-Auth) and post a sample message via the demo endpoint.</p>
  <label>JWT Bearer Token</label>
  <textarea id="token" rows="3" placeholder="eyJhbGciOi..."></textarea>
  <button id="send">Send Demo Post</button>
  <pre id="output">Waiting...</pre>
  <script>
    const btn = document.getElementById('send');
    const out = document.getElementById('output');
    btn.onclick = async () => {
      const token = document.getElementById('token').value.trim();
      if (!token) {
        out.textContent = 'Please provide a JWT token.';
        return;
      }
      out.textContent = 'Sending...';
      try {
        const res = await fetch('/demo/post', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token
          }
        });
        const text = await res.text();
        out.textContent = text;
      } catch (err) {
        out.textContent = 'Error: ' + err;
      }
    };
  </script>
</body>
</html>"#,
    )
}

async fn demo_surreal(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, _) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let author = user.name.clone();
    match state
        .surreal
        .create_demo_post(
            "Surreal demo",
            "Hello from SurrealDB demo endpoint",
            &author,
        )
        .await
    {
        Ok(record) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "record": record
            })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "surreal demo failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateSurrealPost {
    subject: String,
    body: String,
}

async fn surreal_post(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateSurrealPost>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 20, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = validate_content(&payload.subject, &payload.body) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if let Err(resp) = ensure_permission(&state, &ctx, "post_new") {
        return resp.into_response();
    }
    let author = user.name.clone();
    match state
        .surreal
        .create_post(
            &sanitize_input(&payload.subject),
            &sanitize_input(&payload.body),
            &author,
        )
        .await
    {
        Ok(post) => (
            StatusCode::CREATED,
            Json(json!({
                "status": "ok",
                "post": post
            })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create surreal post");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

async fn surreal_posts(
    State(state): State<AppState>,
    _claims: Option<AuthClaims>,
) -> impl IntoResponse {
    match state.surreal.list_posts().await {
        Ok(posts) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "posts": posts
            })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list surreal posts");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateBoardPayload {
    name: String,
    description: Option<String>,
}

async fn create_surreal_board(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(payload): Json<CreateBoardPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 10, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if payload.name.trim().is_empty() || payload.name.trim().len() > 100 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "name must be 1..100 chars"})),
        )
            .into_response();
    }
    if let Err(resp) = ensure_permission(&state, &ctx, "manage_boards") {
        return resp.into_response();
    }
    match state
        .surreal
        .create_board(&payload.name, payload.description.as_deref())
        .await
    {
        Ok(board) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "board": board})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create board");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

async fn surreal_boards(
    State(state): State<AppState>,
    _claims: Option<AuthClaims>,
) -> impl IntoResponse {
    match state.surreal.list_boards().await {
        Ok(boards) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "boards": boards})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list boards");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreateTopicPayload {
    board_id: String,
    subject: String,
    body: String,
}

async fn create_surreal_topic(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreateTopicPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 20, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = validate_content(&payload.subject, &payload.body) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if let Err(resp) = ensure_permission(&state, &ctx, "post_new") {
        return resp.into_response();
    }
    let author = user.name.clone();
    let topic_result: Result<(SurrealTopic, SurrealPost), surrealdb::Error> = async {
        let topic = state
            .surreal
            .create_topic(
                &payload.board_id,
                &sanitize_input(&payload.subject),
                &author,
            )
            .await?;
        // create initial post inside the topic
        let topic_id = topic.id.clone().unwrap_or_default();
        let post = state
            .surreal
            .create_post_in_topic(
                &topic_id,
                &payload.board_id,
                &sanitize_input(&payload.subject),
                &sanitize_input(&payload.body),
                &author,
            )
            .await?;
        Ok((topic, post))
    }
    .await;

    match topic_result {
        Ok((topic, post)) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "topic": topic, "first_post": post})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create topic");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct ListTopicsParams {
    board_id: String,
}

async fn list_surreal_topics(
    State(state): State<AppState>,
    _claims: Option<AuthClaims>,
    Query(params): Query<ListTopicsParams>,
) -> impl IntoResponse {
    match state.surreal.list_topics(&params.board_id).await {
        Ok(topics) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "topics": topics})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list topics");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct CreatePostPayload {
    topic_id: String,
    board_id: String,
    subject: Option<String>,
    body: String,
}

async fn create_surreal_topic_post(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<CreatePostPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c,
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    let key = rate_key(claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 40, Duration::from_secs(60)) {
        return resp.into_response();
    }
    let subject = payload
        .subject
        .clone()
        .unwrap_or_else(|| "Re: topic".into());
    if let Err(resp) = validate_content(&subject, &payload.body) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    // Basic XSS mitigation by sanitizing HTML content
    if let Err(resp) = ensure_permission(&state, &ctx, "post_reply_any") {
        return resp.into_response();
    }
    let author = user.name.clone();
    match state
        .surreal
        .create_post_in_topic(
            &payload.topic_id,
            &payload.board_id,
            &sanitize_input(&subject),
            &sanitize_input(&payload.body),
            &author,
        )
        .await
    {
        Ok(post) => (
            StatusCode::CREATED,
            Json(json!({"status": "ok", "post": post})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to create post");
            (
                StatusCode::BAD_REQUEST,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct ListPostsParams {
    topic_id: String,
}

async fn list_surreal_posts_for_topic(
    State(state): State<AppState>,
    _claims: Option<AuthClaims>,
    Query(params): Query<ListPostsParams>,
) -> impl IntoResponse {
    match state.surreal.list_posts_for_topic(&params.topic_id).await {
        Ok(posts) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "posts": posts})),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to list posts");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

async fn demo_post(State(state): State<AppState>, claims: Option<AuthClaims>) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = enforce_rate(&state, &claims.sub, 20, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = enforce_rate(&state, &claims.sub, 30, Duration::from_secs(60)) {
        return resp.into_response();
    }
    let author = user.name.clone();
    if let Err(resp) = ensure_permission(&state, &ctx, "post_new") {
        return resp.into_response();
    }

    match state.forum_service.persist_post(
        &ctx,
        btc_forum_rust::services::PostSubmission {
            topic_id: None,
            board_id: 0,
            message_id: None,
            subject: "API example".into(),
            body: "Hello from Axum demo endpoint".into(),
            icon: "xx".into(),
            approved: true,
            send_notifications: false,
        },
    ) {
        Ok(posted) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "topic_id": posted.topic_id,
                "post_id": posted.message_id,
                "author": author
            })),
        )
            .into_response(),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "message": err.to_string()})),
        )
            .into_response(),
    }
}

async fn list_users(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(params): Query<AdminUsersQuery>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match state.forum_service.list_members() {
        Ok(members) => {
            let filtered: Vec<_> = members
                .into_iter()
                .filter(|m| {
                    if let Some(ref q) = params.q {
                        m.name.to_lowercase().contains(&q.to_lowercase())
                    } else {
                        true
                    }
                })
                .take(params.limit.unwrap_or(200))
                .collect();
            (
                StatusCode::OK,
                Json(json!({ "status": "ok", "members": filtered })),
            )
                .into_response()
        }
        Err(err) => {
            error!(error = %err, "failed to list members");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

#[derive(Deserialize)]
struct AdminNotifyPayload {
    user_ids: Vec<i64>,
    subject: String,
    body: String,
}

#[derive(Deserialize)]
struct AdminUsersQuery {
    q: Option<String>,
    limit: Option<usize>,
}

#[derive(Deserialize)]
struct AdminPageQuery {
    limit: Option<usize>,
    offset: Option<usize>,
}

async fn admin_notify(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Json(payload): Json<AdminNotifyPayload>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    let key = rate_key(&claims, Some(&addr));
    if let Err(resp) = enforce_rate(&state, &key, 5, Duration::from_secs(60)) {
        return resp.into_response();
    }
    if let Err(resp) = verify_csrf(&headers) {
        return resp.into_response();
    }
    if payload.user_ids.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "user_ids required"})),
        )
            .into_response();
    }
    if payload.user_ids.len() > 50 {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"status": "error", "message": "user_ids too many (max 50)"})),
        )
            .into_response();
    }
    if let Err(resp) = validate_content(&payload.subject, &payload.body) {
        return resp.into_response();
    }
    let message = SendPersonalMessage {
        sender_id: 0,
        sender_name: "admin".into(),
        to: payload.user_ids.clone(),
        bcc: Vec::new(),
        subject: sanitize_input(&payload.subject),
        body: sanitize_input(&payload.body),
    };
    match state.forum_service.send_personal_message(message) {
        Ok(result) => (
            StatusCode::OK,
            Json(json!({"status": "ok", "sent_to": result.recipient_ids })),
        )
            .into_response(),
        Err(err) => {
            error!(error = %err, "failed to send admin notification");
            let _ = state.forum_service.log_action(
                "admin_notify_error",
                None,
                &json!({
                    "error": err.to_string(),
                    "subject": payload.subject,
                    "user_ids": payload.user_ids,
                }),
            );
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

async fn list_bans(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(_): Query<AdminPageQuery>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match state.forum_service.list_ban_rules() {
        Ok(bans) => (StatusCode::OK, Json(json!({"status": "ok", "bans": bans}))).into_response(),
        Err(err) => {
            error!(error = %err, "failed to list bans");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

async fn list_action_logs(
    State(state): State<AppState>,
    claims: Option<AuthClaims>,
    Query(_): Query<AdminPageQuery>,
) -> impl IntoResponse {
    let claims = match require_auth(&claims) {
        Ok(c) => c.clone(),
        Err(resp) => return resp.into_response(),
    };
    let (_user, ctx) = match ensure_user_ctx(&state, &claims).await {
        Ok(value) => value,
        Err(resp) => return resp.into_response(),
    };
    if let Err(resp) = ensure_admin(&ctx) {
        return resp.into_response();
    }
    match state.forum_service.list_action_logs() {
        Ok(logs) => (StatusCode::OK, Json(json!({"status": "ok", "logs": logs}))).into_response(),
        Err(err) => {
            error!(error = %err, "failed to list action logs");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({"status": "error", "message": err.to_string()})),
            )
                .into_response()
        }
    }
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        let mut terminate =
            signal(SignalKind::terminate()).expect("failed to install SIGTERM handler");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = terminate.recv() => {},
        }
    }

    #[cfg(not(unix))]
    {
        tokio::signal::ctrl_c()
            .await
            .expect("failed to install Ctrl+C handler");
    }
}
