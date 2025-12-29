# BTC Forum (Rust)

Rust 2024 版的论坛业务原型，采用内存实现的服务层，用于演示发帖、私信、权限等核心流程。入口在 `src/main.rs`，通过构造 `ForumContext` 并调用控制器方法输出示例结果。

## 快速开始
- 准备：安装 Rust 1.75+。仓库无额外系统依赖。
- 构建：`cargo build`（加 `--release` 获取优化产物）。
- 运行 CLI 示例：`cargo run` 会触发帖子与私信流程并在终端打印。
- 启动 HTTP API（需要 Postgres，先设置 `DATABASE_URL` 和 `JWT_SECRET`）：`cargo run --bin api`，默认监听 `127.0.0.1:3000`。健康检查 `/health`，示例发帖接口 `/demo/post`（需 `Authorization: Bearer <JWT>`，使用内存服务造一个帖子并同步用户到 Postgres，返回 `last_post_id`）。
- 简易前端：启动后访问 `http://127.0.0.1:3000/ui`，在页面填入 JWT（来自认证服务）即可调用 `/demo/post` 观察返回结果。
- SurrealDB 示例：设置 `SURREAL_ENDPOINT` 等环境变量后，可调用：
  - `/demo/surreal`（同样需要 Bearer JWT）写入一条 `demo_posts` 记录；
  - `/surreal/boards`（GET/POST）管理版块；
  - `/surreal/topics`（GET `?board_id=...` / POST `{board_id, subject, body}`）创建/列出主题；
  - `/surreal/topic/posts`（GET `?topic_id=...` / POST `{topic_id, board_id, body, subject?}`）在主题下发帖或查看帖子；
  - `/surreal/post` + `/surreal/posts` 保留为简单写入/列表演示。
- 数据库迁移：安装 `sqlx-cli` 后执行 `sqlx migrate run`（读取 `DATABASE_URL`），初始迁移文件在 `migrations/0001_init.sql`。
- 格式化：`cargo fmt`
- 静态检查：`cargo clippy -- -D warnings`
- 测试：目前无测试，可按惯例添加 `#[cfg(test)]` 单测或 `tests/` 集成测，运行 `cargo test`。

## 目录概览
- `src/main.rs`：演示入口，初始化内存服务并调用控制器。
- `src/controller/`：控制器层，协调上下文与服务。
- `src/services/`：服务与数据模型（含 `InMemoryService::new_with_sample()` 供测试/示例）。
- `src/templates/`：可复用的视图/模板片段。
- `src/db.rs`：Postgres 连接池配置与构建。
- `src/auth.rs`：JWT Claims 提取器（与 Rainbow-Auth 共享 `JWT_SECRET`）。
- `src/surreal.rs`：SurrealDB 连接与示例写入。
- `migrations/`：`sqlx` 迁移脚本（表结构定义）。
- 其它 `src/*.rs`：按领域拆分的业务模块（帖子、私信、注册、权限等）。

## 状态与限制
- 内存原型：无持久化、无网络接口，重启即丢数据。
- 用途：验证业务流程与接口设计；落地时需要替换存储、鉴权、日志与外部集成。

## 贡献提示
- 提交前运行 `cargo fmt` 与 `cargo clippy -- -D warnings` 确保风格一致。
- 添加新逻辑时附带单测或最小可复现示例，方便回归。更多细节见 `AGENTS.md`。 
