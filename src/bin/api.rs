use axum::{
    extract::State,
    http::StatusCode,
    response::{Html, IntoResponse},
    routing::{get, post},
    Json, Router,
};
use chrono::Utc;
use dotenvy::dotenv;
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
};

#[derive(Clone)]
struct AppState {
    db: PgPool,
    forum: InMemoryService,
}

#[tokio::main]
async fn main() {
    dotenv().ok();
    init_tracing();

    let db_config = DbConfig::from_env();
    let db = connect_pool(&db_config).expect("failed to configure postgres pool");

    let forum = InMemoryService::new_with_sample();
    let state = AppState { db, forum };
    let app = Router::new()
        .route("/health", get(health))
        .route("/ui", get(ui))
        .route("/demo/post", post(demo_post))
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
        ),
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
