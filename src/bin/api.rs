use axum::{
    Json, Router,
    extract::{ConnectInfo, Query, State},
    http::{HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use chrono::Utc;
use dotenvy::dotenv;
use serde::Deserialize;
use serde_json::json;
use std::{
    env,
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use tower_http::trace::TraceLayer;

use btc_forum_rust::{
    auth::AuthClaims,
    services::{ForumContext, ForumService, SendPersonalMessage, surreal::SurrealService},
    surreal::{SurrealForumService, SurrealPost, SurrealTopic, SurrealUser, connect_from_env},
};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct AppState {
    surreal: SurrealForumService,
    forum_service: SurrealService,
    rate_limiter: Arc<RateLimiter>,
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

#[cfg(test)]
mod tests {
    use super::*;

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
    let state = AppState {
        surreal,
        forum_service,
        rate_limiter: Arc::new(RateLimiter::new()),
    };
    let app = Router::new()
        .route("/health", get(health))
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
        .layer(
            CorsLayer::new()
                .allow_origin(
                    "http://127.0.0.1:8080"
                        .parse::<HeaderValue>()
                        .expect("invalid CORS origin"),
                )
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                ]),
        )
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
    if let Err(resp) = ensure_permission(&state, &ctx, "post_new") {
        return resp.into_response();
    }
    let author = user.name.clone();
    match state
        .surreal
        .create_post(&payload.subject, &payload.body, &author)
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
    if let Err(resp) = ensure_permission(&state, &ctx, "post_new") {
        return resp.into_response();
    }
    let author = user.name.clone();
    let topic_result: Result<(SurrealTopic, SurrealPost), surrealdb::Error> = async {
        let topic = state
            .surreal
            .create_topic(&payload.board_id, &payload.subject, &author)
            .await?;
        // create initial post inside the topic
        let topic_id = topic.id.clone().unwrap_or_default();
        let post = state
            .surreal
            .create_post_in_topic(
                &topic_id,
                &payload.board_id,
                &payload.subject,
                &payload.body,
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
    if let Err(resp) = ensure_permission(&state, &ctx, "post_reply_any") {
        return resp.into_response();
    }
    let author = user.name.clone();
    match state
        .surreal
        .create_post_in_topic(
            &payload.topic_id,
            &payload.board_id,
            &subject,
            &payload.body,
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
        subject: payload.subject.clone(),
        body: payload.body.clone(),
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
                &json!({"error": err.to_string(), "subject": payload.subject}),
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
