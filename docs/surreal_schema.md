# Surreal 模型约定（初版）

当前 API/CLI 默认使用 SurrealDB，采用以下 collection 字段约定：

## boards
- `id`: Surreal record id（字符串）
- `name`: 标题
- `description`: 描述（可空）
- `created_at`: `time::now()`

索引：按 `created_at` 倒序列出。

## topics
- `id`: Surreal record id
- `board_id`: `boards` 记录 id（字符串）
- `subject`: 标题
- `author`: 作者名称（来自上下文/claims）
- `created_at` / `updated_at`: `time::now()`

索引：按 `board_id` 过滤，`created_at` 倒序。

## posts
- `id`: Surreal record id
- `topic_id`: 主题 id
- `board_id`: 版块 id
- `subject`: 标题（回复默认 `Re: topic`）
- `body`: 正文
- `author`: 作者名称
- `created_at`: `time::now()`

索引：按 `topic_id` 升序列出；也可按 `created_at` 全局倒序查看。

## users（规划）
- `id`: Surreal record id
- `name`: 显示名
- `role`: 角色（如 `admin`/`mod`/`member`/`guest`）
- `permissions`: 数组，按需存储字符串权限（如 `post_new`/`post_reply_any` 等）
- 其他：`created_at`/`updated_at` 等

说明：当前代码使用 `ForumContext.user_info`（内存构造）作为权限来源；后续可从 users 表加载并填充 `permissions`、`is_admin`/`is_mod` 等字段。

## personal_messages（占位）
- 规划字段：`id`、`sender_id`、`recipient_id`、`subject`、`body`、`is_read`、`created_at`
- 当前未在代码中启用，后续落地 PM 流程时补充操作。

说明：
- SurrealService 中的发帖/回帖路径使用上述字段；其余 ForumService 方法目前返回空/占位，后续按需要实现。
- 作者/身份默认取 JWT `sub`，匿名为 `guest`。默认会在缺版块时创建 `General` 版块。
