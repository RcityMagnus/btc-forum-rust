use axum::{
    Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
};
use chrono::Utc;
use dotenvy::dotenv;
use serde::Deserialize;
use serde_json::json;
use sqlx::PgPool;
use std::{env, net::SocketAddr};
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use btc_forum_rust::{
    auth::AuthClaims,
    controller::post::PostController,
    db::{DbConfig, connect_pool, upsert_user_by_sub},
    services::{ForumContext, ForumError, InMemoryService},
    surreal::{
        SurrealClient, SurrealPost, SurrealTopic, connect_from_env, create_board, create_demo_post,
        create_post as surreal_create_post, create_post_in_topic, create_topic, list_boards,
        list_posts as surreal_list_posts, list_posts_for_topic, list_topics,
    },
};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    forum: InMemoryService,
    surreal: SurrealClient,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    init_tracing();

    let db_config = DbConfig::from_env();
    let db = connect_pool(&db_config).expect("failed to configure postgres pool");

    let forum = InMemoryService::new_with_sample();
    let surreal = connect_from_env()
        .await
        .expect("failed to connect to SurrealDB");
    let state = AppState { db, forum, surreal };
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
    let db_status = match sqlx::query_scalar::<_, i32>("select 1")
        .fetch_one(&state.db)
        .await
    {
        Ok(_) => json!({"status": "ok"}),
        Err(err) => {
            error!(error = %err, "database connectivity check failed");
            json!({"status": "error", "message": err.to_string()})
        }
    };

    (
        StatusCode::OK,
        Json(json!({
            "service": "ok",
            "db": db_status,
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

async fn demo_surreal(State(state): State<AppState>, claims: AuthClaims) -> impl IntoResponse {
    match create_demo_post(
        &state.surreal,
        "Surreal demo",
        "Hello from SurrealDB demo endpoint",
        &claims.sub,
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
    claims: AuthClaims,
    Json(payload): Json<CreateSurrealPost>,
) -> impl IntoResponse {
    match surreal_create_post(&state.surreal, &payload.subject, &payload.body, &claims.sub).await {
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

async fn surreal_posts(State(state): State<AppState>, _claims: AuthClaims) -> impl IntoResponse {
    match surreal_list_posts(&state.surreal).await {
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
    _claims: AuthClaims,
    Json(payload): Json<CreateBoardPayload>,
) -> impl IntoResponse {
    match create_board(
        &state.surreal,
        &payload.name,
        payload.description.as_deref(),
    )
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

async fn surreal_boards(State(state): State<AppState>, _claims: AuthClaims) -> impl IntoResponse {
    match list_boards(&state.surreal).await {
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
    claims: AuthClaims,
    Json(payload): Json<CreateTopicPayload>,
) -> impl IntoResponse {
    let topic_result: Result<(SurrealTopic, SurrealPost), surrealdb::Error> = async {
        let topic = create_topic(
            &state.surreal,
            &payload.board_id,
            &payload.subject,
            &claims.sub,
        )
        .await?;
        // create initial post inside the topic
        let topic_id = topic.id.clone().unwrap_or_default();
        let post = create_post_in_topic(
            &state.surreal,
            &topic_id,
            &payload.board_id,
            &payload.subject,
            &payload.body,
            &claims.sub,
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
    _claims: AuthClaims,
    Query(params): Query<ListTopicsParams>,
) -> impl IntoResponse {
    match list_topics(&state.surreal, &params.board_id).await {
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
    claims: AuthClaims,
    Json(payload): Json<CreatePostPayload>,
) -> impl IntoResponse {
    let subject = payload.subject.as_deref().unwrap_or("Re: topic");
    match create_post_in_topic(
        &state.surreal,
        &payload.topic_id,
        &payload.board_id,
        subject,
        &payload.body,
        &claims.sub,
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
    _claims: AuthClaims,
    Query(params): Query<ListPostsParams>,
) -> impl IntoResponse {
    match list_posts_for_topic(&state.surreal, &params.topic_id).await {
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

async fn demo_post(State(state): State<AppState>, claims: AuthClaims) -> impl IntoResponse {
    if let Err(err) = upsert_user_by_sub(&state.db, &claims.sub).await {
        error!(error = %err, "failed to upsert user");
        return (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"status": "error", "message": "failed to sync user"})),
        )
            .into_response();
    }

    let service = state.forum.clone();
    let controller = PostController::new(service);

    let mut ctx = ForumContext::default();
    ctx.board_id = Some(1);
    ctx.user_info.is_guest = false;
    ctx.user_info.permissions.insert("post_new".into());
    ctx.context.set("becomes_approved", true);
    ctx.post_vars.set("subject", "API example");
    ctx.post_vars
        .set("message", "Hello from Axum demo endpoint");

    match controller.post2(&mut ctx) {
        Ok(_) => (
            StatusCode::OK,
            Json(json!({
                "status": "ok",
                "last_post_id": ctx.context.int("last_post_id"),
                "board_id": ctx.board_id
            })),
        )
            .into_response(),
        Err(err) => {
            let status = match err {
                ForumError::PermissionDenied(_) => StatusCode::FORBIDDEN,
                ForumError::Validation(_) => StatusCode::BAD_REQUEST,
                _ => StatusCode::INTERNAL_SERVER_ERROR,
            };
            (
                status,
                Json(json!({ "status": "error", "message": err.to_string() })),
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
