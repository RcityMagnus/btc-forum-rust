use std::env;

use serde_json::Value;
use surrealdb::{
    Surreal,
    engine::remote::http::{Client, Http},
    opt::auth::Root,
};
use tracing::info;

pub type SurrealClient = Surreal<Client>;

fn normalize_endpoint(raw: String) -> String {
    let ep = raw.trim().to_string();
    if ep.starts_with("http://") || ep.starts_with("https://") {
        ep
    } else {
        format!("http://{ep}")
    }
}

/// Connect to SurrealDB using environment variables, defaults to local root account.
pub async fn connect_from_env() -> Result<SurrealClient, surrealdb::Error> {
    let endpoint_raw =
        env::var("SURREAL_ENDPOINT").unwrap_or_else(|_| "http://127.0.0.1:8000".into());
    let endpoint = normalize_endpoint(endpoint_raw);
    let ns = env::var("SURREAL_NAMESPACE").unwrap_or_else(|_| "auth".into());
    let db = env::var("SURREAL_DATABASE").unwrap_or_else(|_| "main".into());
    let user = env::var("SURREAL_USER").unwrap_or_else(|_| "root".into());
    let pass = env::var("SURREAL_PASS").unwrap_or_else(|_| "root".into());

    info!(endpoint, namespace = %ns, database = %db, "connecting to SurrealDB (HTTP)");
    let client = Surreal::new::<Http>(&endpoint).await?;
    client
        .signin(Root {
            username: &user,
            password: &pass,
        })
        .await?;
    client.use_ns(&ns).use_db(&db).await?;
    Ok(client)
}

/// Create a demo post record in SurrealDB.
pub async fn create_demo_post(
    client: &SurrealClient,
    subject: &str,
    body: &str,
    user: &str,
) -> Result<Value, surrealdb::Error> {
    let subject = subject.to_owned();
    let body = body.to_owned();
    let user = user.to_owned();
    let mut response = client
        .query(
            r#"
            CREATE demo_posts CONTENT {
                subject: $subject,
                body: $body,
                user: $user,
                created_at: time::now()
            } RETURN *;
            "#,
        )
        .bind(("subject", subject))
        .bind(("body", body))
        .bind(("user", user))
        .await?;

    let created: Option<Value> = response.take(0)?;
    Ok(created.unwrap_or(Value::Null))
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SurrealPost {
    pub id: Option<String>,
    pub topic_id: Option<String>,
    pub board_id: Option<String>,
    pub subject: String,
    pub body: String,
    pub author: String,
    pub created_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SurrealTopic {
    pub id: Option<String>,
    pub board_id: String,
    pub subject: String,
    pub author: String,
    pub created_at: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SurrealBoard {
    pub id: Option<String>,
    pub name: String,
    pub description: Option<String>,
    pub created_at: Option<String>,
}

pub async fn create_post(
    client: &SurrealClient,
    subject: &str,
    body: &str,
    user: &str,
) -> Result<SurrealPost, surrealdb::Error> {
    let subject = subject.to_owned();
    let body = body.to_owned();
    let user = user.to_owned();
    let mut response = client
        .query(
            r#"
            CREATE posts CONTENT {
                topic_id: null,
                board_id: null,
                subject: $subject,
                body: $body,
                author: $user,
                created_at: time::now()
            } RETURN meta::id(id) as id, topic_id, board_id, subject, body, author, created_at;
            "#,
        )
        .bind(("subject", subject))
        .bind(("body", body))
        .bind(("user", user))
        .await?;

    let created: Option<SurrealPost> = response.take(0)?;
    Ok(created.unwrap_or_else(|| SurrealPost {
        id: None,
        topic_id: None,
        board_id: None,
        subject: subject.to_string(),
        body: body.to_string(),
        author: user.to_string(),
        created_at: None,
    }))
}

pub async fn list_posts(client: &SurrealClient) -> Result<Vec<SurrealPost>, surrealdb::Error> {
    let mut response = client
        .query(
            r#"
            SELECT meta::id(id) as id, topic_id, board_id, subject, body, author, created_at
            FROM posts
            ORDER BY created_at DESC
            LIMIT 50;
            "#,
        )
        .await?;

    let posts: Vec<SurrealPost> = response.take(0)?;
    Ok(posts)
}

pub async fn create_board(
    client: &SurrealClient,
    name: &str,
    description: Option<&str>,
) -> Result<SurrealBoard, surrealdb::Error> {
    let name = name.to_owned();
    let description_owned = description.map(|d| d.to_owned());
    let mut response = client
        .query(
            r#"
            CREATE boards CONTENT {
                name: $name,
                description: $description,
                created_at: time::now()
            } RETURN meta::id(id) as id, name, description, created_at;
            "#,
        )
        .bind(("name", name))
        .bind(("description", description_owned))
        .await?;

    let board: Option<SurrealBoard> = response.take(0)?;
    Ok(board.unwrap_or_else(|| SurrealBoard {
        id: None,
        name: name.to_string(),
        description: description.map(|d| d.to_string()),
        created_at: None,
    }))
}

pub async fn list_boards(client: &SurrealClient) -> Result<Vec<SurrealBoard>, surrealdb::Error> {
    let mut response = client
        .query(
            r#"
            SELECT meta::id(id) as id, name, description, created_at
            FROM boards
            ORDER BY created_at DESC;
            "#,
        )
        .await?;
    let boards: Vec<SurrealBoard> = response.take(0)?;
    Ok(boards)
}

pub async fn create_topic(
    client: &SurrealClient,
    board_id: &str,
    subject: &str,
    author: &str,
) -> Result<SurrealTopic, surrealdb::Error> {
    let board_id = board_id.to_owned();
    let subject = subject.to_owned();
    let author = author.to_owned();
    let mut response = client
        .query(
            r#"
            CREATE topics CONTENT {
                board_id: $board_id,
                subject: $subject,
                author: $author,
                created_at: time::now(),
                updated_at: time::now()
            } RETURN meta::id(id) as id, board_id, subject, author, created_at, updated_at;
            "#,
        )
        .bind(("board_id", board_id))
        .bind(("subject", subject))
        .bind(("author", author))
        .await?;

    let topic: Option<SurrealTopic> = response.take(0)?;
    Ok(topic.unwrap_or_else(|| SurrealTopic {
        id: None,
        board_id: board_id.to_string(),
        subject: subject.to_string(),
        author: author.to_string(),
        created_at: None,
        updated_at: None,
    }))
}

pub async fn list_topics(
    client: &SurrealClient,
    board_id: &str,
) -> Result<Vec<SurrealTopic>, surrealdb::Error> {
    let board_id = board_id.to_owned();
    let mut response = client
        .query(
            r#"
            SELECT meta::id(id) as id, board_id, subject, author, created_at, updated_at
            FROM topics
            WHERE board_id = $board_id
            ORDER BY created_at DESC
            LIMIT 50;
            "#,
        )
        .bind(("board_id", board_id))
        .await?;
    let topics: Vec<SurrealTopic> = response.take(0)?;
    Ok(topics)
}

pub async fn create_post_in_topic(
    client: &SurrealClient,
    topic_id: &str,
    board_id: &str,
    subject: &str,
    body: &str,
    author: &str,
) -> Result<SurrealPost, surrealdb::Error> {
    let topic_id = topic_id.to_owned();
    let board_id = board_id.to_owned();
    let subject = subject.to_owned();
    let body = body.to_owned();
    let author = author.to_owned();
    let mut response = client
        .query(
            r#"
            CREATE posts CONTENT {
                topic_id: $topic_id,
                board_id: $board_id,
                subject: $subject,
                body: $body,
                author: $author,
                created_at: time::now()
            } RETURN meta::id(id) as id, topic_id, board_id, subject, body, author, created_at;
            "#,
        )
        .bind(("topic_id", topic_id))
        .bind(("board_id", board_id))
        .bind(("subject", subject))
        .bind(("body", body))
        .bind(("author", author))
        .await?;

    let post: Option<SurrealPost> = response.take(0)?;
    Ok(post.unwrap_or_else(|| SurrealPost {
        id: None,
        topic_id: Some(topic_id.to_string()),
        board_id: Some(board_id.to_string()),
        subject: subject.to_string(),
        body: body.to_string(),
        author: author.to_string(),
        created_at: None,
    }))
}

pub async fn list_posts_for_topic(
    client: &SurrealClient,
    topic_id: &str,
) -> Result<Vec<SurrealPost>, surrealdb::Error> {
    let topic_id = topic_id.to_owned();
    let mut response = client
        .query(
            r#"
            SELECT meta::id(id) as id, topic_id, board_id, subject, body, author, created_at
            FROM posts
            WHERE topic_id = $topic_id
            ORDER BY created_at ASC
            LIMIT 200;
            "#,
        )
        .bind(("topic_id", topic_id))
        .await?;

    let posts: Vec<SurrealPost> = response.take(0)?;
    Ok(posts)
}
