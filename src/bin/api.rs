use axum::{
    Json, Router,
    extract::{Query, State},
    http::{HeaderValue, Method, StatusCode},
    response::{Html, IntoResponse},
    routing::{get, post},
};
use chrono::Utc;
use dotenvy::dotenv;
use serde::Deserialize;
use serde_json::json;
use std::{env, net::SocketAddr};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use btc_forum_rust::{
    auth::AuthClaims,
    services::{surreal::SurrealService, ForumContext, ForumService},
    surreal::{SurrealForumService, SurrealPost, SurrealTopic, connect_from_env},
};
use tower_http::cors::CorsLayer;

#[derive(Clone)]
struct AppState {
    surreal: SurrealForumService,
    forum_service: SurrealService,
}

fn claims_sub(claims: &Option<AuthClaims>) -> String {
    claims
        .as_ref()
        .map(|c| c.sub.clone())
        .unwrap_or_else(|| "guest".into())
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

fn apply_claims_to_context(ctx: &mut ForumContext, claims: &AuthClaims) {
    ctx.user_info.is_guest = false;
    ctx.user_info.name = claims.sub.clone();
    if let Some(role) = &claims.role {
        match role.as_str() {
            "admin" => ctx.user_info.is_admin = true,
            "mod" => ctx.user_info.is_mod = true,
            _ => {}
        }
    }
    if let Some(perms) = &claims.permissions {
        ctx.user_info
            .permissions
            .extend(perms.iter().cloned());
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
    let state = AppState { surreal, forum_service };
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
        .layer(
            CorsLayer::new()
                .allow_origin(
                    "http://127.0.0.1:8080"
                        .parse::<HeaderValue>()
                        .expect("invalid CORS origin"),
                )
                .allow_methods([Method::GET, Method::POST, Method::OPTIONS])
                .allow_headers([axum::http::header::AUTHORIZATION, axum::http::header::CONTENT_TYPE]),
        )
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
    let sub = match require_auth(&claims) {
        Ok(c) => c.sub.clone(),
        Err(resp) => return resp.into_response(),
    };
    match state
        .surreal
        .create_demo_post("Surreal demo", "Hello from SurrealDB demo endpoint", &sub)
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
    Json(payload): Json<CreateSurrealPost>,
) -> impl IntoResponse {
    let sub = match require_auth(&claims) {
        Ok(c) => c.sub.clone(),
        Err(resp) => return resp.into_response(),
    };
    match state
        .surreal
        .create_post(&payload.subject, &payload.body, &sub)
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

async fn surreal_posts(State(state): State<AppState>, _claims: Option<AuthClaims>) -> impl IntoResponse {
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
    _claims: Option<AuthClaims>,
    Json(payload): Json<CreateBoardPayload>,
) -> impl IntoResponse {
    if let Err(resp) = require_auth(&_claims) {
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

async fn surreal_boards(State(state): State<AppState>, _claims: Option<AuthClaims>) -> impl IntoResponse {
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
    Json(payload): Json<CreateTopicPayload>,
) -> impl IntoResponse {
    let sub = match require_auth(&claims) {
        Ok(c) => c.sub.clone(),
        Err(resp) => return resp.into_response(),
    };
    let topic_result: Result<(SurrealTopic, SurrealPost), surrealdb::Error> = async {
        let topic = state
            .surreal
            .create_topic(&payload.board_id, &payload.subject, &sub)
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
                &sub,
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
    Json(payload): Json<CreatePostPayload>,
) -> impl IntoResponse {
    let sub = match require_auth(&claims) {
        Ok(c) => c.sub.clone(),
        Err(resp) => return resp.into_response(),
    };
    let subject = payload.subject.as_deref().unwrap_or("Re: topic");
    match state
        .surreal
        .create_post_in_topic(
            &payload.topic_id,
            &payload.board_id,
            subject,
            &payload.body,
            &sub,
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
    let sub = match require_auth(&claims) {
        Ok(c) => c.sub.clone(),
        Err(resp) => return resp.into_response(),
    };
    let mut ctx = ForumContext::default();
    if let Some(claims) = &claims {
        apply_claims_to_context(&mut ctx, claims);
    } else {
        ctx.user_info.name = sub.clone();
        ctx.user_info.is_guest = false;
        ctx.user_info
            .permissions
            .extend(["post_new".into(), "post_reply_any".into(), "pm_read".into(), "pm_send".into()]);
    }

    match state
        .forum_service
        .persist_post(
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
        )
    {
        Ok(posted) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "topic_id": posted.topic_id,
                "post_id": posted.message_id,
                "author": sub
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
