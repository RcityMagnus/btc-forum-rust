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

#[derive(Deserialize)]
struct AuthResponse {
    status: String,
    token: String,
    user: AuthUser,
}

#[derive(Deserialize)]
struct AuthUser {
    name: String,
    role: Option<String>,
    permissions: Option<Vec<String>>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct BoardAccessEntry {
    id: i64,
    name: String,
    allowed_groups: Vec<i64>,
}

#[derive(Serialize)]
struct BoardAccessPayload {
    board_id: i64,
    allowed_groups: Vec<i64>,
}

#[derive(Deserialize)]
struct BoardAccessResponse {
    status: String,
    entries: Vec<BoardAccessEntry>,
}

#[derive(Deserialize)]
struct UpdateBoardAccessResponse {
    status: String,
    board_id: i64,
    allowed_groups: Vec<i64>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
struct BoardPermissionEntry {
    board_id: i64,
    group_id: i64,
    allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Deserialize)]
struct BoardPermissionsResponse {
    status: String,
    entries: Vec<BoardPermissionEntry>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
struct BoardPermissionsPayload {
    board_id: i64,
    group_id: i64,
    allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Deserialize)]
struct UpdateBoardPermissionsResponse {
    status: String,
    board_id: i64,
    group_id: i64,
    allow: Vec<String>,
    deny: Vec<String>,
}

#[derive(Serialize)]
struct LoginPayload {
    username: String,
    password: String,
}

#[derive(Serialize)]
struct RegisterPayload {
    username: String,
    password: String,
    role: Option<String>,
    permissions: Option<Vec<String>>,
}

fn main() {
    launch(App);
}

fn save_token_to_storage(token: &str) {
    if let Some(win) = window() {
        if let Ok(Some(storage)) = win.local_storage() {
            let _ = storage.set_item("jwt_token", token);
        }
    }
}

fn load_token_from_storage() -> Option<String> {
    window()
        .and_then(|win| win.local_storage().ok().flatten())
        .and_then(|storage| storage.get_item("jwt_token").ok().flatten())
}

fn App() -> Element {
    let mut api_base = use_signal(|| "http://127.0.0.1:3000".to_string());
    let mut token = use_signal(|| load_token_from_storage().unwrap_or_default());
    let mut status = use_signal(|| "等待操作...".to_string());
    let mut csrf_token = use_signal(|| "".to_string());
    let start_path = window()
        .and_then(|win| win.location().pathname().ok())
        .unwrap_or_else(|| "/".to_string());
    let mut is_admin_page = use_signal(move || start_path.starts_with("/admin"));
    let mut login_username = use_signal(|| "".to_string());
    let mut login_password = use_signal(|| "".to_string());
    let mut register_username = use_signal(|| "".to_string());
    let mut register_password = use_signal(|| "".to_string());
    let mut register_admin = use_signal(|| false);

    let boards = use_signal(Vec::<Board>::new);
    let topics = use_signal(Vec::<Topic>::new);
    let posts = use_signal(Vec::<Post>::new);
    let board_access = use_signal(Vec::<BoardAccessEntry>::new);

    let mut selected_board = use_signal(|| "".to_string());
    let mut selected_topic = use_signal(|| "".to_string());

    let mut new_board_name = use_signal(|| "".to_string());
    let mut new_board_desc = use_signal(|| "".to_string());
    let mut new_topic_subject = use_signal(|| "".to_string());
    let mut new_topic_body = use_signal(|| "".to_string());
    let mut new_post_subject = use_signal(|| "".to_string());
    let mut new_post_body = use_signal(|| "".to_string());
    let mut access_board_id = use_signal(|| "".to_string());
    let mut access_groups = use_signal(|| "".to_string());
    let mut perm_board_id = use_signal(|| "".to_string());
    let mut perm_group_id = use_signal(|| "".to_string());
    let mut perm_allow = use_signal(|| "".to_string());
    let mut perm_deny = use_signal(|| "".to_string());
    let board_permissions = use_signal(Vec::<BoardPermissionEntry>::new);

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

    let login_action = move || {
        let base = api_base.read().clone();
        let user = login_username.read().trim().to_string();
        let pass = login_password.read().to_string();
        let mut status = status.clone();
        let mut token_sig = token.clone();
        if user.is_empty() || pass.is_empty() {
            status.set("请输入用户名和密码".into());
            return;
        }
        spawn(async move {
            status.set("登录中...".into());
            let payload = LoginPayload {
                username: user.clone(),
                password: pass.clone(),
            };
            match post_json::<AuthResponse, _>(&base, "/auth/login", "", "", &payload).await {
                Ok(resp) => {
                    save_token_to_storage(&resp.token);
                    token_sig.set(resp.token);
                    status.set(format!("登录成功：{}", resp.user.name));
                }
                Err(err) => status.set(format!("登录失败：{err}")),
            }
        });
    };

    let register_action = move || {
        let base = api_base.read().clone();
        let user = register_username.read().trim().to_string();
        let pass = register_password.read().to_string();
        let is_admin = register_admin.read();
        let mut status = status.clone();
        let mut token_sig = token.clone();
        if user.is_empty() || pass.is_empty() {
            status.set("请输入注册用户名和密码".into());
            return;
        }
        let role = if *is_admin { Some("admin".to_string()) } else { None };
        let perms = if *is_admin {
            Some(vec![
                "post_new".into(),
                "post_reply_any".into(),
                "manage_boards".into(),
                "admin".into(),
            ])
        } else {
            Some(vec!["post_new".into(), "post_reply_any".into()])
        };
        spawn(async move {
            status.set("注册中...".into());
            let payload = RegisterPayload {
                username: user.clone(),
                password: pass.clone(),
                role,
                permissions: perms,
            };
            match post_json::<AuthResponse, _>(&base, "/auth/register", "", "", &payload).await {
                Ok(resp) => {
                    save_token_to_storage(&resp.token);
                    token_sig.set(resp.token);
                    status.set(format!("注册成功并登录：{}", resp.user.name));
                }
                Err(err) => status.set(format!("注册失败：{err}")),
            }
        });
    };

    let load_access = move || {
        let base = api_base.read().clone();
        let jwt = token.read().clone();
        let csrf = csrf_token.read().clone();
        let mut status = status.clone();
        let mut access = board_access.clone();
        if jwt.trim().is_empty() {
            status.set("请先登录/粘贴管理员 JWT".into());
            return;
        }
        spawn(async move {
            status.set("加载版块访问控制...".into());
            match get_json::<BoardAccessResponse>(&base, "/admin/board_access", &jwt, &csrf).await {
                Ok(resp) => {
                    access.set(resp.entries);
                    status.set("版块访问控制已加载".into());
                }
                Err(err) => status.set(format!("加载失败：{err}")),
            }
        });
    };

    let update_access = move || {
        let base = api_base.read().clone();
        let jwt = token.read().clone();
        let csrf = csrf_token.read().clone();
        let mut status = status.clone();
        let mut access = board_access.clone();
        let board_id_val = access_board_id.read().trim().to_string();
        let groups_raw = access_groups.read().clone();

        if jwt.trim().is_empty() {
            status.set("请先登录/粘贴管理员 JWT".into());
            return;
        }
        let board_id: i64 = match board_id_val.parse() {
            Ok(id) => id,
            Err(_) => {
                status.set("请输入有效的版块 ID".into());
                return;
            }
        };
        let mut groups = Vec::new();
        if !groups_raw.trim().is_empty() {
            for part in groups_raw.split(',') {
                if let Ok(id) = part.trim().parse::<i64>() {
                    groups.push(id);
                }
            }
        }

        spawn(async move {
            status.set("更新版块访问控制...".into());
            let payload = BoardAccessPayload {
                board_id,
                allowed_groups: groups.clone(),
            };
            match post_json::<UpdateBoardAccessResponse, _>(
                &base,
                "/admin/board_access",
                &jwt,
                &csrf,
                &payload,
            )
            .await
            {
                Ok(resp) => {
                    let mut current = access.read().clone();
                    if let Some(entry) = current.iter_mut().find(|e| e.id == resp.board_id) {
                        entry.allowed_groups = resp.allowed_groups.clone();
                    } else {
                        current.push(BoardAccessEntry {
                            id: resp.board_id,
                            name: String::new(),
                            allowed_groups: resp.allowed_groups.clone(),
                        });
                    }
                    access.set(current);
                    status.set("版块访问控制已更新".into());
                }
                Err(err) => status.set(format!("更新失败：{err}")),
            }
        });
    };

    let load_permissions = move || {
        let base = api_base.read().clone();
        let jwt = token.read().clone();
        let csrf = csrf_token.read().clone();
        let mut status = status.clone();
        let mut perms_sig = board_permissions.clone();
        if jwt.trim().is_empty() {
            status.set("请先登录/粘贴管理员 JWT".into());
            return;
        }
        spawn(async move {
            status.set("加载版块权限...".into());
            match get_json::<BoardPermissionsResponse>(&base, "/admin/board_permissions", &jwt, &csrf).await {
                Ok(resp) => {
                    perms_sig.set(resp.entries);
                    status.set("版块权限已加载".into());
                }
                Err(err) => status.set(format!("加载失败：{err}")),
            }
        });
    };

    let update_permissions = move || {
        let base = api_base.read().clone();
        let jwt = token.read().clone();
        let csrf = csrf_token.read().clone();
        let mut status = status.clone();
        let mut perms_sig = board_permissions.clone();
        let bid_str = perm_board_id.read().trim().to_string();
        let gid_str = perm_group_id.read().trim().to_string();
        let allow_raw = perm_allow.read().clone();
        let deny_raw = perm_deny.read().clone();

        if jwt.trim().is_empty() {
            status.set("请先登录/粘贴管理员 JWT".into());
            return;
        }
        let board_id: i64 = match bid_str.parse() {
            Ok(id) => id,
            Err(_) => {
                status.set("请输入有效的版块 ID".into());
                return;
            }
        };
        let group_id: i64 = match gid_str.parse() {
            Ok(id) => id,
            Err(_) => {
                status.set("请输入有效的分组 ID".into());
                return;
            }
        };
        let parse_perms = |raw: String| {
            raw.split(',')
                .filter_map(|p| {
                    let v = p.trim();
                    if v.is_empty() {
                        None
                    } else {
                        Some(v.to_string())
                    }
                })
                .collect::<Vec<_>>()
        };
        let allow = parse_perms(allow_raw);
        let deny = parse_perms(deny_raw);

        spawn(async move {
            status.set("更新版块权限...".into());
            let payload = BoardPermissionsPayload {
                board_id,
                group_id,
                allow: allow.clone(),
                deny: deny.clone(),
            };
            match post_json::<UpdateBoardPermissionsResponse, _>(
                &base,
                "/admin/board_permissions",
                &jwt,
                &csrf,
                &payload,
            )
            .await
            {
                Ok(resp) => {
                    let mut current = perms_sig.read().clone();
                    if let Some(entry) = current
                        .iter_mut()
                        .find(|e| e.board_id == resp.board_id && e.group_id == resp.group_id)
                    {
                        entry.allow = resp.allow.clone();
                        entry.deny = resp.deny.clone();
                    } else {
                        current.push(BoardPermissionEntry {
                            board_id: resp.board_id,
                            group_id: resp.group_id,
                            allow: resp.allow.clone(),
                            deny: resp.deny.clone(),
                        });
                    }
                    perms_sig.set(current);
                    status.set("版块权限已更新".into());
                }
                Err(err) => status.set(format!("更新失败：{err}")),
            }
        });
    };

    let is_admin = *is_admin_page.read();

    rsx! {
        style { {STYLE} }
        div { class: "app-shell",
            nav { class: "top-nav",
                div { class: "brand",
                    span { class: "brand__dot" }
                    span { "BTC Forum" }
                    span { class: "brand__tag", "alpha" }
                }
                div { class: "nav-links",
                    a {
                        class: if !is_admin { "nav-link active" } else { "nav-link" },
                        href: "/",
                        onclick: move |_| {
                            is_admin_page.set(false);
                            if let Some(win) = window() {
                                let _ = win.location().set_href("/");
                            }
                        },
                        "论坛"
                    }
                    a {
                        class: if is_admin { "nav-link active" } else { "nav-link" },
                        href: "/admin",
                        onclick: move |_| {
                            is_admin_page.set(true);
                            if let Some(win) = window() {
                                let _ = win.location().set_href("/admin");
                            }
                        },
                        "管理后台"
                    }
                }
            }

            div { class: "status-bar", "状态：{status.read()}" }

            if !is_admin {
                { rsx! {
                    section { class: "hero",
                        div { class: "hero__copy",
                            span { class: "pill", "Bitcoin Forum · Testnet" }
                            h1 { "比特币技术 & 社区实验室" }
                            p { "直连 SurrealDB 的论坛 Demo：注册、发帖、回帖与权限全部在这里自测。" }
                            div { class: "hero__actions",
                                button { onclick: move |_| load_boards(), "加载版块/主题" }
                                a { class: "ghost-btn", href: "/admin", "管理后台 (/admin)" }
                            }
                        }
                        div { class: "hero__panel",
                            div { class: "stat",
                                span { "当前 API" }
                                strong { "{api_base.read()}" }
                            }
                            div { class: "stat-row",
                                div { class: "stat-box", strong { "{boards.read().len()}" } span { "版块" } }
                                div { class: "stat-box", strong { "{topics.read().len()}" } span { "主题" } }
                                div { class: "stat-box", strong { "{posts.read().len()}" } span { "帖子" } }
                            }
                        }
                    }

                    section { class: "panel",
                        h2 { "连接配置" }
                        div { class: "grid two",
                            div {
                                label { "API 基址" }
                                input {
                                    value: "{api_base.read()}",
                                    oninput: move |evt| api_base.set(evt.value()),
                                    placeholder: "http://127.0.0.1:3000",
                                }
                            }
                            div {
                                label { "CSRF Token" }
                                input {
                                    value: "{csrf_token.read()}",
                                    oninput: move |evt| csrf_token.set(evt.value()),
                                    placeholder: "可选：后端启用 CSRF 时填写",
                                }
                            }
                        }
                        label { "JWT Token（可从登录/注册获取）" }
                        textarea {
                            value: "{token.read()}",
                            oninput: move |evt| token.set(evt.value()),
                            rows: "3",
                            placeholder: "Bearer token（来自认证服务）",
                        }
                        div { class: "actions",
                            button { onclick: move |_| load_boards(), "加载版块" }
                            button { onclick: move |_| load_topics(), "加载主题" }
                            button { onclick: move |_| load_posts(), "加载帖子" }
                            button { class: "ghost-btn", onclick: move |_| { token.set("".into()); save_token_to_storage(""); status.set("已清空本地 token".into()); }, "清空 Token" }
                        }
                    }

                section { class: "panel",
                    h2 { "登录 / 注册" }
                    div { class: "grid two",
                        div { class: "card-ghost",
                            h3 { "登录" }
                            label { "用户名" }
                            input {
                                value: "{login_username.read()}",
                                oninput: move |evt| login_username.set(evt.value()),
                                placeholder: "用户名",
                            }
                            label { "密码" }
                            input {
                                r#type: "password",
                                value: "{login_password.read()}",
                                oninput: move |evt| login_password.set(evt.value()),
                                placeholder: "密码",
                            }
                            button { onclick: move |_| login_action(), "登录" }
                        }
                        div { class: "card-ghost",
                            h3 { "注册 - 必填信息" }
                            p { class: "muted",
                                "提示：论坛其他页面可在无 JS 情况下浏览，但注册为了防刷需要 JavaScript。若 IP 曾被滥用，登录后可能需要支付小额注册费（本 Demo 不会扣费）。"
                            }
                            ul { class: "list",
                                li { class: "item", "Choose username: 仅用于站内标识" }
                                li { class: "item", "Email: 建议使用可用邮箱（可填 yourname@invalid.bitcointalk.org）" }
                                li { class: "item", "Hide email address from public? 可选" }
                                li { class: "item", "Password / Verify password" }
                                li { class: "item", "Visual verification / reCAPTCHA：本 Demo 不校验，仅占位" }
                            }
                            label { "用户名" }
                            input {
                                value: "{register_username.read()}",
                                oninput: move |evt| register_username.set(evt.value()),
                                placeholder: "新用户名",
                            }
                            label { "密码" }
                            input {
                                r#type: "password",
                                value: "{register_password.read()}",
                                oninput: move |evt| register_password.set(evt.value()),
                                placeholder: "密码",
                            }
                            label { class: "checkbox",
                                input {
                                    r#type: "checkbox",
                                    checked: *register_admin.read(),
                                    oninput: move |_| {
                                        let current = *register_admin.read();
                                        register_admin.set(!current);
                                    },
                                }
                                span { "注册为管理员（含 manage_boards/admin 权限）" }
                            }
                            p { class: "muted", "当前后端只接收用户名/密码（Email/CAPTCHA 为占位文案，未提交到后端）。" }
                            button { onclick: move |_| register_action(), "注册并登录" }
                        }
                    }
                }

                    section { class: "grid two gap",
                        div { class: "panel",
                            div { class: "panel__header",
                                h3 { "版块" }
                                span { class: "muted", "在 SurrealDB 中创建/选择版块" }
                            }
                            div { class: "stack",
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
                            ul { class: "list board-list",
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

                        div { class: "panel",
                            div { class: "panel__header",
                                h3 { "主题" }
                                span { class: "muted", "选择版块后创建主题" }
                            }
                            div { class: "stack",
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
                            ul { class: "list topic-list",
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
                                            div { class: "meta", "作者: {topic.author} · 更新时间: {topic.updated_at.clone().unwrap_or_default()}" }
                                        }
                                    }
                                })}
                            }
                        }
                    }

                    section { class: "panel",
                        div { class: "panel__header",
                            h3 { "帖子 / 回复" }
                            span { class: "muted", "选择主题后回复" }
                        }
                        div { class: "stack",
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

                        ul { class: "list post-list",
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
                } }
            } else {
                section { class: "hero hero--admin",
                    div { class: "hero__copy",
                        span { class: "pill", "Admin" }
                        h1 { "论坛管理后台" }
                        p { "管理 SurrealDB 中的 board_access 与 board_permissions，适合站点配置与灰度测试。" }
                        div { class: "hero__actions",
                            button { onclick: move |_| load_access(), "加载访问控制" }
                            button { onclick: move |_| load_permissions(), "加载版块权限" }
                        }
                    }
                    div { class: "hero__panel",
                        div { class: "stat",
                            span { "API" }
                            strong { "{api_base.read()}" }
                        }
                        div { class: "stat-row",
                            div { class: "stat-box", strong { "{board_access.read().len()}" } span { "访问规则" } }
                            div { class: "stat-box", strong { "{board_permissions.read().len()}" } span { "权限规则" } }
                        }
                    }
                }

                section { class: "panel",
                    h2 { "连接 / 凭证" }
                    div { class: "grid two",
                        div {
                            label { "API 基址" }
                            input {
                                value: "{api_base.read()}",
                                oninput: move |evt| api_base.set(evt.value()),
                                placeholder: "http://127.0.0.1:3000",
                            }
                        }
                        div {
                            label { "CSRF Token" }
                            input {
                                value: "{csrf_token.read()}",
                                oninput: move |evt| csrf_token.set(evt.value()),
                                placeholder: "写操作需要的 CSRF Token",
                            }
                        }
                    }
                    label { "管理员 JWT" }
                    textarea {
                        value: "{token.read()}",
                        oninput: move |evt| token.set(evt.value()),
                        rows: "3",
                        placeholder: "需要包含 manage_boards / admin 权限",
                    }
                    div { class: "actions",
                        button { onclick: move |_| load_access(), "加载访问规则" }
                        button { onclick: move |_| load_permissions(), "加载版块权限" }
                        button { class: "ghost-btn", onclick: move |_| { token.set("".into()); save_token_to_storage(""); status.set("已清空本地 token".into()); }, "清空 Token" }
                    }
                }

                section { class: "panel",
                    div { class: "panel__header",
                        h3 { "版块访问控制 board_access" }
                        span { class: "muted", "填入 board_id 与允许的 group 列表" }
                    }
                    div { class: "grid two",
                        div {
                            label { "版块 ID" }
                            input {
                                value: "{access_board_id.read()}",
                                oninput: move |evt| access_board_id.set(evt.value()),
                                placeholder: "board_id (数字)",
                            }
                            label { "允许分组（逗号分隔数字）" }
                            input {
                                value: "{access_groups.read()}",
                                oninput: move |evt| access_groups.set(evt.value()),
                                placeholder: "例如：1,2,3",
                            }
                            div { class: "actions",
                                button { onclick: move |_| update_access(), "更新访问规则" }
                            }
                        }
                        div {
                            h4 { "当前访问规则" }
                            ul { class: "list",
                                { board_access.read().iter().cloned().map(|entry| {
                                    let groups = entry.allowed_groups.iter().map(|g| g.to_string()).collect::<Vec<_>>().join(", ");
                                    rsx! {
                                        li { class: "item",
                                            strong { "Board #{entry.id}" }
                                            div { class: "meta", "允许分组: {groups}" }
                                        }
                                    }
                                })}
                            }
                        }
                    }
                }

                section { class: "panel",
                    div { class: "panel__header",
                        h3 { "版块权限 allow/deny" }
                        span { class: "muted", "board_permissions：填入 allow / deny 列表" }
                    }
                    div { class: "grid two",
                        div {
                            label { "版块 ID" }
                            input {
                                value: "{perm_board_id.read()}",
                                oninput: move |evt| perm_board_id.set(evt.value()),
                                placeholder: "board_id",
                            }
                            label { "分组 ID" }
                            input {
                                value: "{perm_group_id.read()}",
                                oninput: move |evt| perm_group_id.set(evt.value()),
                                placeholder: "group_id",
                            }
                            label { "Allow 权限（逗号分隔）" }
                            input {
                                value: "{perm_allow.read()}",
                                oninput: move |evt| perm_allow.set(evt.value()),
                                placeholder: "post_new,post_reply_any",
                            }
                            label { "Deny 权限（逗号分隔）" }
                            input {
                                value: "{perm_deny.read()}",
                                oninput: move |evt| perm_deny.set(evt.value()),
                                placeholder: "manage_boards",
                            }
                            div { class: "actions",
                                button { onclick: move |_| update_permissions(), "更新权限" }
                            }
                        }
                        div {
                            h4 { "当前权限规则" }
                            ul { class: "list",
                                { board_permissions.read().iter().cloned().map(|entry| {
                                    let allow = if entry.allow.is_empty() { "无".into() } else { entry.allow.join(", ") };
                                    let deny = if entry.deny.is_empty() { "无".into() } else { entry.deny.join(", ") };
                                    rsx! {
                                        li { class: "item",
                                            strong { "Board #{entry.board_id} / Group #{entry.group_id}" }
                                            div { class: "meta", "Allow: {allow}" }
                                            div { class: "meta", "Deny: {deny}" }
                                        }
                                    }
                                })}
                            }
                        }
                    }
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
:root {
    --bg: #0d1118;
    --panel: #131a26;
    --muted: #9da9c0;
    --text: #e8edf5;
    --accent: #f7931a;
    --accent2: #3d8bfd;
    --border: rgba(255,255,255,0.08);
    --radius: 14px;
}
* { box-sizing: border-box; }
body { margin: 0; background: radial-gradient(circle at 18% 20%, rgba(247,147,26,0.08), transparent 26%), radial-gradient(circle at 82% 12%, rgba(61,139,253,0.12), transparent 24%), #0f141e; color: var(--text); font-family: "Inter", "Noto Sans SC", system-ui, -apple-system, sans-serif; }
a { color: inherit; text-decoration: none; }
.app-shell { max-width: 1200px; margin: 0 auto; padding: 18px 18px 36px; display: flex; flex-direction: column; gap: 14px; }
.top-nav { position: sticky; top: 0; z-index: 10; display: flex; align-items: center; justify-content: space-between; padding: 10px 14px; border: 1px solid var(--border); background: rgba(13,17,24,0.9); backdrop-filter: blur(8px); border-radius: 14px; box-shadow: 0 10px 40px rgba(0,0,0,0.35); }
.brand { display: flex; align-items: center; gap: 10px; font-weight: 800; letter-spacing: 0.4px; text-transform: uppercase; }
.brand__dot { width: 10px; height: 10px; border-radius: 50%; background: var(--accent); box-shadow: 0 0 12px rgba(247,147,26,0.8); }
.brand__tag { padding: 2px 8px; border-radius: 999px; background: rgba(61,139,253,0.15); color: #9dc3ff; font-size: 12px; }
.nav-links { display: flex; gap: 8px; align-items: center; }
.nav-link { padding: 8px 12px; border-radius: 10px; border: 1px solid var(--border); background: rgba(255,255,255,0.03); color: var(--text); font-weight: 600; cursor: pointer; }
.nav-link.active { background: linear-gradient(120deg, var(--accent), var(--accent2)); color: #0b0e15; box-shadow: 0 8px 28px rgba(61,139,253,0.3); }
.status-bar { border: 1px dashed var(--border); border-radius: 12px; padding: 10px 12px; color: var(--muted); background: rgba(255,255,255,0.02); }
.hero { display: grid; grid-template-columns: 1.3fr 1fr; gap: 18px; padding: 20px; border-radius: 16px; border: 1px solid var(--border); background: radial-gradient(circle at 15% 20%, rgba(247,147,26,0.15), transparent 40%), radial-gradient(circle at 85% 15%, rgba(61,139,253,0.16), transparent 35%), #0f141e; box-shadow: 0 16px 50px rgba(0,0,0,0.5); }
.hero__copy h1 { margin: 6px 0 8px; font-size: 28px; letter-spacing: 0.3px; }
.hero__copy p { margin: 0 0 12px; color: var(--muted); }
.hero__actions { display: flex; gap: 10px; flex-wrap: wrap; }
.hero__panel { background: rgba(255,255,255,0.04); border: 1px solid var(--border); border-radius: 12px; padding: 14px; display: flex; flex-direction: column; gap: 10px; }
.stat { display: flex; flex-direction: column; gap: 4px; color: var(--muted); }
.stat strong { color: var(--text); font-size: 15px; }
.stat-row { display: grid; grid-template-columns: repeat(auto-fit, minmax(110px, 1fr)); gap: 8px; }
.stat-box { background: rgba(0,0,0,0.25); border: 1px solid var(--border); border-radius: 10px; padding: 10px; text-align: center; }
.stat-box strong { font-size: 20px; display: block; color: #fbc27a; }
.pill { display: inline-block; padding: 4px 10px; border-radius: 999px; background: rgba(247,147,26,0.15); color: #ffbd71; font-weight: 700; letter-spacing: 0.6px; text-transform: uppercase; font-size: 12px; }
.ghost-btn { padding: 9px 12px; border-radius: 10px; border: 1px solid var(--border); background: transparent; color: var(--text); cursor: pointer; }
.panel { background: var(--panel); border: 1px solid var(--border); border-radius: var(--radius); padding: 16px; box-shadow: 0 12px 36px rgba(0,0,0,0.35); }
.panel h2, .panel h3, .panel h4 { margin: 0 0 10px; }
.panel__header { display: flex; align-items: baseline; justify-content: space-between; gap: 10px; }
.muted { color: var(--muted); font-size: 13px; }
.grid { display: grid; gap: 14px; }
.grid.two { grid-template-columns: repeat(auto-fit, minmax(320px, 1fr)); }
.grid.two.gap { gap: 16px; }
label { display: block; margin-top: 6px; font-weight: 700; color: var(--text); }
input, textarea { width: 100%; margin-top: 6px; padding: 10px 12px; border-radius: 10px; border: 1px solid var(--border); background: rgba(255,255,255,0.04); color: var(--text); }
input:focus, textarea:focus { outline: 1px solid var(--accent); border-color: var(--accent); }
textarea { resize: vertical; }
.actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 12px; }
button { padding: 10px 14px; border: none; border-radius: 10px; background: linear-gradient(120deg, var(--accent), var(--accent2)); color: #0b0e13; font-weight: 800; cursor: pointer; transition: transform 0.1s ease, box-shadow 0.1s ease; letter-spacing: 0.2px; }
button:hover { transform: translateY(-1px); box-shadow: 0 10px 22px rgba(61,139,253,0.35); }
.card-ghost { background: rgba(255,255,255,0.02); border: 1px dashed var(--border); border-radius: 12px; padding: 12px; }
.checkbox { display: flex; align-items: center; gap: 8px; margin-top: 8px; }
.stack { display: flex; flex-direction: column; gap: 8px; }
.list { list-style: none; padding: 0; margin: 12px 0 0 0; display: flex; flex-direction: column; gap: 10px; }
.item { background: rgba(255,255,255,0.03); border: 1px solid var(--border); padding: 10px 12px; border-radius: 12px; cursor: pointer; transition: border-color 0.1s ease, background 0.1s ease; }
.item:hover { border-color: var(--accent); }
.item.selected { border-color: var(--accent2); background: rgba(61,139,253,0.09); }
.meta { color: var(--muted); font-size: 13px; margin-top: 4px; }
.post-list .item { cursor: default; }
.board-list strong, .topic-list strong { color: #f7c58a; }
.status { margin-top: 8px; color: #9bd5ff; }
.hero--admin { background: radial-gradient(circle at 18% 20%, rgba(61,139,253,0.2), transparent 38%), radial-gradient(circle at 80% 10%, rgba(247,147,26,0.16), transparent 30%), #0e1521; }
@media (max-width: 900px) { .hero { grid-template-columns: 1fr; } }
@media (max-width: 640px) { .top-nav { flex-direction: column; align-items: flex-start; gap: 10px; } .nav-links { width: 100%; flex-wrap: wrap; } }
"#;
