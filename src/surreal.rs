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
    // Surreal's HTTP client expects a host:port string. Strip any scheme and trailing slash to
    // avoid building URLs like `http://http://host:port/health`.
    let ep = raw.trim().trim_end_matches('/').to_string();
    ep.strip_prefix("http://")
        .or_else(|| ep.strip_prefix("https://"))
        .unwrap_or(&ep)
        .to_string()
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
        .bind(("subject", subject.clone()))
        .bind(("body", body.clone()))
        .bind(("user", user.clone()))
        .await?;

    let created: Option<SurrealPost> = response.take(0)?;
    Ok(created.unwrap_or_else(|| SurrealPost {
        id: None,
        topic_id: None,
        board_id: None,
        subject,
        body,
        author: user,
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
        .bind(("name", name.clone()))
        .bind(("description", description_owned.clone()))
        .await?;

    let board: Option<SurrealBoard> = response.take(0)?;
    Ok(board.unwrap_or_else(|| SurrealBoard {
        id: None,
        name,
        description: description_owned,
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
        .bind(("board_id", board_id.clone()))
        .bind(("subject", subject.clone()))
        .bind(("author", author.clone()))
        .await?;

    let topic: Option<SurrealTopic> = response.take(0)?;
    Ok(topic.unwrap_or_else(|| SurrealTopic {
        id: None,
        board_id,
        subject,
        author,
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
        .bind(("topic_id", topic_id.clone()))
        .bind(("board_id", board_id.clone()))
        .bind(("subject", subject.clone()))
        .bind(("body", body.clone()))
        .bind(("author", author.clone()))
        .await?;

    let post: Option<SurrealPost> = response.take(0)?;
    Ok(post.unwrap_or_else(|| SurrealPost {
        id: None,
        topic_id: Some(topic_id),
        board_id: Some(board_id),
        subject,
        body,
        author,
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

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SurrealUser {
    pub id: Option<String>,
    pub name: String,
    pub role: Option<String>,
    pub permissions: Option<Vec<String>>,
    pub created_at: Option<String>,
}

pub async fn get_user_by_name(
    client: &SurrealClient,
    name: &str,
) -> Result<Option<SurrealUser>, surrealdb::Error> {
    let name = name.to_owned();
    let mut response = client
        .query(
            r#"
            SELECT meta::id(id) as id, name, role, permissions, created_at
            FROM users
            WHERE name = $name
            LIMIT 1;
            "#,
        )
        .bind(("name", name))
        .await?;
    let user: Option<SurrealUser> = response.take(0)?;
    Ok(user)
}

pub async fn create_user(
    client: &SurrealClient,
    name: &str,
    role: Option<&str>,
    permissions: Option<&[String]>,
) -> Result<SurrealUser, surrealdb::Error> {
    let name = name.to_owned();
    let role = role
        .map(|r| r.to_owned())
        .unwrap_or_else(|| "member".into());
    let perms = permissions.map(|p| p.to_owned()).unwrap_or_default();
    let mut response = client
        .query(
            r#"
            CREATE users CONTENT {
                name: $name,
                role: $role,
                permissions: $permissions,
                created_at: time::now()
            } RETURN meta::id(id) as id, name, role, permissions, created_at;
            "#,
        )
        .bind(("name", name.clone()))
        .bind(("role", role.clone()))
        .bind(("permissions", perms.clone()))
        .await?;
    let user: Option<SurrealUser> = response.take(0)?;
    Ok(user.unwrap_or_else(|| SurrealUser {
        id: None,
        name,
        role: Some(role),
        permissions: Some(perms),
        created_at: None,
    }))
}

pub async fn ensure_user(
    client: &SurrealClient,
    name: &str,
    role: Option<&str>,
    permissions: Option<&[String]>,
) -> Result<SurrealUser, surrealdb::Error> {
    if let Some(user) = get_user_by_name(client, name).await? {
        return Ok(user);
    }
    create_user(client, name, role, permissions).await
}

/// Thin service wrapper to encapsulate SurrealDB forum operations.
#[derive(Clone)]
pub struct SurrealForumService {
    client: SurrealClient,
}

impl SurrealForumService {
    pub fn new(client: SurrealClient) -> Self {
        Self { client }
    }

    pub fn client(&self) -> &SurrealClient {
        &self.client
    }

    /// Lightweight connectivity check.
    pub async fn health(&self) -> Result<(), surrealdb::Error> {
        self.client.query("RETURN true;").await?;
        Ok(())
    }

    pub async fn create_demo_post(
        &self,
        subject: &str,
        body: &str,
        user: &str,
    ) -> Result<Value, surrealdb::Error> {
        create_demo_post(&self.client, subject, body, user).await
    }

    pub async fn create_board(
        &self,
        name: &str,
        description: Option<&str>,
    ) -> Result<SurrealBoard, surrealdb::Error> {
        create_board(&self.client, name, description).await
    }

    pub async fn list_boards(&self) -> Result<Vec<SurrealBoard>, surrealdb::Error> {
        list_boards(&self.client).await
    }

    pub async fn create_topic(
        &self,
        board_id: &str,
        subject: &str,
        author: &str,
    ) -> Result<SurrealTopic, surrealdb::Error> {
        create_topic(&self.client, board_id, subject, author).await
    }

    pub async fn list_topics(&self, board_id: &str) -> Result<Vec<SurrealTopic>, surrealdb::Error> {
        list_topics(&self.client, board_id).await
    }

    pub async fn create_post(
        &self,
        subject: &str,
        body: &str,
        user: &str,
    ) -> Result<SurrealPost, surrealdb::Error> {
        create_post(&self.client, subject, body, user).await
    }

    pub async fn create_post_in_topic(
        &self,
        topic_id: &str,
        board_id: &str,
        subject: &str,
        body: &str,
        author: &str,
    ) -> Result<SurrealPost, surrealdb::Error> {
        create_post_in_topic(&self.client, topic_id, board_id, subject, body, author).await
    }

    pub async fn list_posts_for_topic(
        &self,
        topic_id: &str,
    ) -> Result<Vec<SurrealPost>, surrealdb::Error> {
        list_posts_for_topic(&self.client, topic_id).await
    }

    pub async fn list_posts(&self) -> Result<Vec<SurrealPost>, surrealdb::Error> {
        list_posts(&self.client).await
    }

    pub async fn ensure_user(
        &self,
        name: &str,
        role: Option<&str>,
        permissions: Option<&[String]>,
    ) -> Result<SurrealUser, surrealdb::Error> {
        ensure_user(&self.client, name, role, permissions).await
    }
}
