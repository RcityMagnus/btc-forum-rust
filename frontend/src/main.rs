use dioxus::prelude::*;
use reqwasm::http::{Request, RequestCredentials};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use web_sys::{window, wasm_bindgen::JsCast};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct Board {
    id: Option<String>,
    name: String,
    description: Option<String>,
    created_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct Topic {
    id: Option<String>,
    board_id: String,
    subject: String,
    author: String,
    created_at: Option<String>,
    updated_at: Option<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct Post {
    id: Option<String>,
    topic_id: Option<String>,
    board_id: Option<String>,
    subject: String,
    body: String,
    author: String,
    created_at: Option<String>,
}

#[derive(Deserialize)]
struct BoardsResponse {
    status: String,
    boards: Vec<Board>,
}

#[derive(Deserialize)]
struct BoardResponse {
    status: String,
    board: Board,
}

#[derive(Deserialize)]
struct TopicsResponse {
    status: String,
    topics: Vec<Topic>,
}

#[derive(Deserialize)]
struct PostsResponse {
    status: String,
    posts: Vec<Post>,
}

#[derive(Deserialize)]
struct TopicCreateResponse {
    status: String,
    topic: Topic,
    first_post: Post,
}

#[derive(Deserialize)]
struct PostResponse {
    status: String,
    post: Post,
}

fn main() {
    launch(App);
}

fn App() -> Element {
    let mut api_base = use_signal(|| "http://127.0.0.1:3000".to_string());
    let mut token = use_signal(|| "".to_string());
let status = use_signal(|| "等待操作...".to_string());
    let mut csrf_token = use_signal(|| "".to_string());

    let boards = use_signal(Vec::<Board>::new);
    let topics = use_signal(Vec::<Topic>::new);
    let posts = use_signal(Vec::<Post>::new);

    let mut selected_board = use_signal(|| "".to_string());
    let mut selected_topic = use_signal(|| "".to_string());

    let mut new_board_name = use_signal(|| "".to_string());
    let mut new_board_desc = use_signal(|| "".to_string());
    let mut new_topic_subject = use_signal(|| "".to_string());
    let mut new_topic_body = use_signal(|| "".to_string());
    let mut new_post_subject = use_signal(|| "".to_string());
    let mut new_post_body = use_signal(|| "".to_string());

    let load_boards = move || {
        let base = api_base.read().clone();
        let jwt = token.read().clone();
        let csrf = csrf_token.read().clone();
        let mut status = status.clone();
        let mut boards = boards.clone();
        let mut selected_board = selected_board.clone();
        spawn(async move {
            status.set("加载版块中...".into());
            match get_json::<BoardsResponse>(&base, "/surreal/boards", &jwt, &csrf).await {
                Ok(resp) => {
                    selected_board.set(resp.boards.get(0).and_then(|b| b.id.clone()).unwrap_or_default());
                    boards.set(resp.boards);
                    status.set("版块加载完成".into());
                }
                Err(err) => status.set(format!("加载版块失败：{err}")),
            }
        });
    };

    let load_topics = move || {
        let base = api_base.read().clone();
        let jwt = token.read().clone();
        let csrf = csrf_token.read().clone();
        let mut status = status.clone();
        let mut topics = topics.clone();
        let selected_board_id = selected_board.read().clone();
        let mut selected_topic = selected_topic.clone();

        if selected_board_id.is_empty() {
            status.set("请先选择版块".into());
            return;
        }

        spawn(async move {
            status.set("加载主题中...".into());
            let path = format!("/surreal/topics?board_id={selected_board_id}");
            match get_json::<TopicsResponse>(&base, &path, &jwt, &csrf).await {
                Ok(resp) => {
                    selected_topic.set(resp.topics.get(0).and_then(|t| t.id.clone()).unwrap_or_default());
                    topics.set(resp.topics);
                    status.set("主题加载完成".into());
                }
                Err(err) => status.set(format!("加载主题失败：{err}")),
            }
        });
    };

    let load_posts = move || {
        let base = api_base.read().clone();
        let jwt = token.read().clone();
        let csrf = csrf_token.read().clone();
        let mut status = status.clone();
        let mut posts = posts.clone();
        let selected_topic_id = selected_topic.read().clone();

        if selected_topic_id.is_empty() {
            status.set("请先选择主题".into());
            return;
        }

        spawn(async move {
            status.set("加载帖子中...".into());
            let path = format!("/surreal/topic/posts?topic_id={selected_topic_id}");
            match get_json::<PostsResponse>(&base, &path, &jwt, &csrf).await {
                Ok(resp) => {
                    posts.set(resp.posts);
                    status.set("帖子加载完成".into());
                }
                Err(err) => status.set(format!("加载帖子失败：{err}")),
            }
        });
    };

    rsx! {
        style { {STYLE} }
        div { class: "container",
            header {
                h1 { "BTC Forum (Dioxus / Surreal)" }
                p { "填入 API 基址和 JWT，直接调用 Surreal 路由体验版块/主题/发帖。" }
            }

            section { class: "card",
                h2 { "基础配置" }
                label { "API 基址" }
                input {
                    value: "{api_base.read()}",
                    oninput: move |evt| api_base.set(evt.value()),
                    placeholder: "http://127.0.0.1:3000",
                }
                label { "JWT Token" }
                textarea {
                    value: "{token.read()}",
                    oninput: move |evt| token.set(evt.value()),
                    rows: "3",
                    placeholder: "Bearer token（来自认证服务）",
                }
                label { "CSRF Token" }
                input {
                    value: "{csrf_token.read()}",
                    oninput: move |evt| csrf_token.set(evt.value()),
                    placeholder: "可选：用于通过 CSRF 校验",
                }
                div { class: "actions",
                    button { onclick: move |_| load_boards(), "加载版块" }
                    button { onclick: move |_| load_topics(), "加载主题" }
                    button { onclick: move |_| load_posts(), "加载帖子" }
                }
                p { class: "status", "{status.read()}" }
            }

            section { class: "card grid",
                div {
                    h3 { "版块" }
                    div { class: "input-row",
                        input {
                            value: "{new_board_name.read()}",
                            oninput: move |evt| new_board_name.set(evt.value()),
                            placeholder: "版块名称",
                        }
                        input {
                            value: "{new_board_desc.read()}",
                            oninput: move |evt| new_board_desc.set(evt.value()),
                            placeholder: "描述（可选）",
                        }
                        button {
                            onclick: move |_| {
                                let base = api_base.read().clone();
                                let jwt = token.read().clone();
                                let mut status = status.clone();
                                let mut boards = boards.clone();
                                let name = new_board_name.read().clone();
                                let desc = new_board_desc.read().clone();
                                let mut selected_board = selected_board.clone();
                                let csrf = csrf_token.read().clone();

                                if name.trim().is_empty() {
                                    status.set("请输入版块名称".into());
                                    return;
                                }

                                spawn(async move {
                                    status.set("创建版块中...".into());
                                    let body = CreateBoardPayload { name: name.clone(), description: if desc.trim().is_empty() { None } else { Some(desc.clone()) } };
                                    match post_json::<BoardResponse, _>(&base, "/surreal/boards", &jwt, &csrf, &body).await {
                                        Ok(resp) => {
                                            selected_board.set(resp.board.id.clone().unwrap_or_default());
                                            boards.set({
                                                let mut next = boards.read().clone();
                                                next.insert(0, resp.board);
                                                next
                                            });
                                            status.set("版块创建完成".into());
                                        }
                                        Err(err) => status.set(format!("创建版块失败：{err}")),
                                    }
                                });
                            },
                            "新建版块"
                        }
                    }
                    ul { class: "list",
                        { boards.read().iter().cloned().map(|board| {
                            let id = board.id.clone().unwrap_or_default();
                            let selected = selected_board.read().as_str() == id.as_str();
                            rsx! {
                                li { class: if selected { "item selected" } else { "item" },
                                    onclick: move |_| {
                                        selected_board.set(id.clone());
                                        load_topics();
                                    },
                                    strong { "{board.name}" }
                                    div { class: "meta", "{board.description.clone().unwrap_or_default()}" }
                                }
                            }
                        })}
                    }
                }

                div {
                    h3 { "主题" }
                    div { class: "input-row",
                        input {
                            value: "{new_topic_subject.read()}",
                            oninput: move |evt| new_topic_subject.set(evt.value()),
                            placeholder: "主题标题",
                        }
                        textarea {
                            value: "{new_topic_body.read()}",
                            oninput: move |evt| new_topic_body.set(evt.value()),
                            placeholder: "首帖内容",
                            rows: "2",
                        }
                        button {
                            onclick: move |_| {
                                let base = api_base.read().clone();
                                let jwt = token.read().clone();
                                let mut status = status.clone();
                                let mut topics = topics.clone();
                                let mut posts = posts.clone();
                                let board_id = selected_board.read().clone();
                                let subject = new_topic_subject.read().clone();
                                let body = new_topic_body.read().clone();
                                let mut selected_topic = selected_topic.clone();
                                let csrf = csrf_token.read().clone();

                                if board_id.is_empty() {
                                    status.set("请选择一个版块".into());
                                    return;
                                }
                                if subject.trim().is_empty() || body.trim().is_empty() {
                                    status.set("主题标题和内容不能为空".into());
                                    return;
                                }

                                spawn(async move {
                                    status.set("创建主题中...".into());
                                    let payload = CreateTopicPayload { board_id: board_id.clone(), subject: subject.clone(), body: body.clone() };
                                    match post_json::<TopicCreateResponse, _>(&base, "/surreal/topics", &jwt, &csrf, &payload).await {
                                        Ok(resp) => {
                                            selected_topic.set(resp.topic.id.clone().unwrap_or_default());
                                            topics.set({
                                                let mut next = topics.read().clone();
                                                next.insert(0, resp.topic);
                                                next
                                            });
                                            posts.set({
                                                let mut next = Vec::new();
                                                next.push(resp.first_post);
                                                next
                                            });
                                            status.set("主题创建完成".into());
                                        }
                                        Err(err) => status.set(format!("创建主题失败：{err}")),
                                    }
                                });
                            },
                            "新建主题"
                        }
                    }
                    ul { class: "list",
                        { topics.read().iter().cloned().map(|topic| {
                            let tid = topic.id.clone().unwrap_or_default();
                            let selected = selected_topic.read().as_str() == tid.as_str();
                            rsx! {
                                li { class: if selected { "item selected" } else { "item" },
                                    onclick: move |_| {
                                        selected_topic.set(tid.clone());
                                        load_posts();
                                    },
                                    strong { "{topic.subject}" }
                                    div { class: "meta", "作者: {topic.author} | 更新时间: {topic.updated_at.clone().unwrap_or_default()}" }
                                }
                            }
                        })}
                    }
                }
            }

            section { class: "card",
                h3 { "回复 / 发帖" }
                div { class: "input-row",
                    input {
                        value: "{new_post_subject.read()}",
                        oninput: move |evt| new_post_subject.set(evt.value()),
                        placeholder: "可选标题（默认 Re: topic）",
                    }
                    textarea {
                        value: "{new_post_body.read()}",
                        oninput: move |evt| new_post_body.set(evt.value()),
                        rows: "3",
                        placeholder: "回复内容",
                    }
                    button {
                        onclick: move |_| {
                            let base = api_base.read().clone();
                            let jwt = token.read().clone();
                            let mut status = status.clone();
                            let mut posts = posts.clone();
                            let board_id = selected_board.read().clone();
                            let topic_id = selected_topic.read().clone();
                            let subject = new_post_subject.read().clone();
                            let body = new_post_body.read().clone();
                            let csrf = csrf_token.read().clone();

                            if board_id.is_empty() || topic_id.is_empty() {
                                status.set("请先选择版块和主题".into());
                                return;
                            }
                            if body.trim().is_empty() {
                                status.set("回复内容不能为空".into());
                                return;
                            }

                                spawn(async move {
                                    status.set("发送帖子中...".into());
                                let payload = CreatePostPayload {
                                    topic_id: topic_id.clone(),
                                    board_id: board_id.clone(),
                                    subject: if subject.trim().is_empty() { None } else { Some(subject.clone()) },
                                    body: body.clone(),
                                };
                                match post_json::<PostResponse, _>(&base, "/surreal/topic/posts", &jwt, &csrf, &payload).await {
                                    Ok(resp) => {
                                        posts.set({
                                            let mut next = posts.read().clone();
                                            next.push(resp.post);
                                            next
                                        });
                                        status.set("帖子已发送".into());
                                    }
                                    Err(err) => status.set(format!("发送失败：{err}")),
                                }
                            });
                        },
                        "发送"
                    }
                }

                ul { class: "list",
                    { posts.read().iter().cloned().map(|post| {
                        rsx! {
                            li { class: "item",
                                strong { "{post.subject}" }
                                div { class: "meta", "作者: {post.author} | 时间: {post.created_at.clone().unwrap_or_default()}" }
                                p { "{post.body}" }
                            }
                        }
                    })}
                }
            }
        }
    }
}

#[derive(Serialize)]
struct CreateBoardPayload {
    name: String,
    description: Option<String>,
}

#[derive(Serialize)]
struct CreateTopicPayload {
    board_id: String,
    subject: String,
    body: String,
}

#[derive(Serialize)]
struct CreatePostPayload {
    topic_id: String,
    board_id: String,
    subject: Option<String>,
    body: String,
}

fn set_csrf_cookie(token: &str) {
    if token.trim().is_empty() {
        return;
    }
    if let Some(win) = window() {
        if let Some(doc) = win.document() {
            if let Ok(html_doc) = doc.dyn_into::<web_sys::HtmlDocument>() {
                let _ = html_doc.set_cookie(&format!("XSRF-TOKEN={}; Path=/", token));
            }
        }
    }
}

async fn get_json<T: DeserializeOwned>(
    base: &str,
    path: &str,
    token: &str,
    csrf: &str,
) -> Result<T, String> {
    let url = format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'));
    let mut req = Request::get(&url);
    if !token.trim().is_empty() {
        req = req.header("Authorization", &format!("Bearer {}", token.trim()));
    }
    if !csrf.trim().is_empty() {
        set_csrf_cookie(csrf);
        req = req.header("X-CSRF-TOKEN", csrf.trim());
    }
    let resp = req
        .credentials(RequestCredentials::Include)
        .send()
        .await
        .map_err(|e| format!("网络错误: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("读取响应失败: {e}"))?;
    if !resp.ok() {
        return Err(format!("HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("解析失败: {e}，原始响应: {text}"))
}

async fn post_json<T: DeserializeOwned, B: Serialize>(
    base: &str,
    path: &str,
    token: &str,
    csrf: &str,
    body: &B,
) -> Result<T, String> {
    let url = format!("{}/{}", base.trim_end_matches('/'), path.trim_start_matches('/'));
    let mut req = Request::post(&url).body(serde_json::to_string(body).map_err(|e| e.to_string())?);
    if !token.trim().is_empty() {
        req = req.header("Authorization", &format!("Bearer {}", token.trim()));
    }
    if !csrf.trim().is_empty() {
        set_csrf_cookie(csrf);
        req = req.header("X-CSRF-TOKEN", csrf.trim());
    }
    let resp = req
        .header("Content-Type", "application/json")
        .credentials(RequestCredentials::Include)
        .send()
        .await
        .map_err(|e| format!("网络错误: {e}"))?;
    let status = resp.status();
    let text = resp.text().await.map_err(|e| format!("读取响应失败: {e}"))?;
    if !resp.ok() {
        return Err(format!("HTTP {status}: {text}"));
    }
    serde_json::from_str(&text).map_err(|e| format!("解析失败: {e}，原始响应: {text}"))
}

const STYLE: &str = r#"
* { box-sizing: border-box; }
body { font-family: "Inter", system-ui, -apple-system, sans-serif; background: linear-gradient(135deg, #0f172a, #111827); color: #e5e7eb; padding: 24px; }
.container { max-width: 1200px; margin: 0 auto; display: flex; flex-direction: column; gap: 16px; }
header h1 { margin: 0; }
.card { background: rgba(255,255,255,0.04); border: 1px solid rgba(255,255,255,0.08); border-radius: 12px; padding: 16px; box-shadow: 0 10px 40px rgba(0,0,0,0.35); }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); gap: 12px; }
label { display: block; margin-top: 8px; font-weight: 600; }
input, textarea { width: 100%; padding: 10px 12px; margin-top: 6px; background: rgba(255,255,255,0.06); border: 1px solid rgba(255,255,255,0.1); border-radius: 8px; color: #e5e7eb; }
input:focus, textarea:focus { outline: 1px solid #22d3ee; border-color: #22d3ee; }
.actions { display: flex; gap: 10px; margin-top: 12px; flex-wrap: wrap; }
button { padding: 10px 14px; border: none; border-radius: 8px; background: linear-gradient(135deg, #22d3ee, #6366f1); color: #0b1120; font-weight: 700; cursor: pointer; transition: transform 0.1s ease, box-shadow 0.1s ease; }
button:hover { transform: translateY(-1px); box-shadow: 0 8px 24px rgba(99,102,241,0.35); }
.status { margin-top: 8px; color: #a5b4fc; }
.list { list-style: none; padding: 0; margin: 12px 0 0 0; display: flex; flex-direction: column; gap: 8px; }
.item { background: rgba(255,255,255,0.03); border: 1px solid rgba(255,255,255,0.07); padding: 10px 12px; border-radius: 10px; cursor: pointer; transition: border-color 0.1s ease, background 0.1s ease; }
.item:hover { border-color: #22d3ee; }
.item.selected { border-color: #22d3ee; background: rgba(34,211,238,0.08); }
.meta { color: #9ca3af; font-size: 13px; margin-top: 4px; }
.input-row { display: flex; flex-direction: column; gap: 8px; }
@media (max-width: 768px) { body { padding: 12px; } .grid { grid-template-columns: 1fr; } }
"#;
