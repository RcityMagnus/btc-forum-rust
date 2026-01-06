use crate::services::{
    ActionLogEntry, AttachmentRecord, AttachmentUpload, BanLogEntry, BanRule, BoardAccessEntry,
    BoardListOptions, BoardSummary, CalendarEvent, DraftStorage, ForumContext, ForumError,
    ForumService, GroupAssignType, GroupMember, MemberRecord, MembergroupData,
    MembergroupListEntry, MembergroupListType, MembergroupSettings, MembergroupSummary,
    MessageData, MessageEditData, NotifyPrefs, PermissionChange, PermissionGroupContext,
    PermissionProfile, PermissionSnapshot, PersonalMessageDetail, PersonalMessageFolder,
    PersonalMessageLabel, PersonalMessageOverview, PersonalMessagePage, PersonalMessagePeer,
    PersonalMessageSearchQuery, PersonalMessageSendResult, PersonalMessageSummary, PmDraftRecord,
    PmPreferenceState, PollData, PostedMessage, QuoteContent, SendPersonalMessage,
    SessionCheckMode, TopicPostingContext,
};
use crate::surreal::{
    SurrealClient, create_board as surreal_create_board,
    create_post_in_topic as surreal_create_post_in_topic, create_topic as surreal_create_topic,
    get_user_by_name, list_boards as surreal_list_boards,
    list_posts_for_topic as surreal_list_posts_for_topic,
};
use chrono::{TimeZone, Utc};
use serde::Deserialize;
use serde_json::Value;

/// Minimal Surreal-backed ForumService implementation.
///
/// Only a subset of methods are implemented to support posting workflows used by controllers.
#[derive(Clone)]
pub struct SurrealService {
    client: SurrealClient,
}

impl SurrealService {
    pub fn new(client: SurrealClient) -> Self {
        Self { client }
    }

    fn ensure_board(&self, ctx: &ForumContext) -> Result<String, ForumError> {
        // Use ctx.board_id if provided; otherwise fetch or create a default board.
        if let Some(id) = ctx
            .board_info
            .string("surreal_id")
            .or_else(|| ctx.context.string("surreal_board_id"))
        {
            return Ok(id);
        }
        if let Some(board_id) = ctx.board_id {
            // Caller provided a numeric id; convert to string for Surreal queries.
            return Ok(board_id.to_string());
        }

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let boards = rt
            .block_on(surreal_list_boards(&self.client))
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        if let Some(id) = boards.first().and_then(|b| b.id.clone()) {
            return Ok(id);
        }
        let created = rt
            .block_on(surreal_create_board(
                &self.client,
                "General",
                Some("Default board"),
            ))
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(created.id.unwrap_or_else(|| "board:default".into()))
    }

    fn unsupported(feature: &str) -> ForumError {
        ForumError::Internal(format!("{feature} not supported in SurrealService"))
    }

    fn parse_ts(ms: i64) -> chrono::DateTime<Utc> {
        Utc.timestamp_millis_opt(ms)
            .single()
            .unwrap_or_else(Utc::now)
    }
}

impl ForumService for SurrealService {
    fn load_language(&self, _ctx: &mut ForumContext, _lang: &str) -> Result<(), ForumError> {
        Ok(())
    }

    fn load_template(&self, _ctx: &mut ForumContext, _template: &str) -> Result<(), ForumError> {
        Ok(())
    }

    fn call_hook(&self, _ctx: &mut ForumContext, _hook: &str) -> Result<(), ForumError> {
        Ok(())
    }

    fn get_notify_prefs(&self, _user_id: i64) -> Result<NotifyPrefs, ForumError> {
        Ok(NotifyPrefs {
            msg_auto_notify: false,
        })
    }

    fn boards_allowed_to(
        &self,
        _ctx: &ForumContext,
        _permissions: &[String],
    ) -> Result<Vec<i64>, ForumError> {
        Ok(vec![0])
    }

    fn get_board_list(
        &self,
        _ctx: &ForumContext,
        _options: &BoardListOptions,
    ) -> Result<Vec<BoardSummary>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let boards = rt
            .block_on(surreal_list_boards(&self.client))
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(boards
            .into_iter()
            .enumerate()
            .map(|(idx, b)| BoardSummary {
                id: idx as i64 + 1,
                name: b.name,
            })
            .collect())
    }

    fn check_session(
        &self,
        _ctx: &ForumContext,
        _mode: SessionCheckMode,
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn allowed_to(
        &self,
        ctx: &ForumContext,
        permission: &str,
        _boards: Option<&[i64]>,
        _any: bool,
    ) -> bool {
        if ctx.user_info.is_admin {
            return true;
        }
        if ctx.user_info.is_mod && permission.starts_with("post_") {
            return true;
        }
        ctx.user_info.permissions.contains(permission)
    }

    fn redirect_exit(&self, _url: &str) -> Result<(), ForumError> {
        Ok(())
    }

    fn find_topic_id_by_msg(&self, _msg_id: i64) -> Result<Option<i64>, ForumError> {
        Err(ForumError::Internal(
            "find_topic_id_by_msg not implemented in SurrealService".into(),
        ))
    }

    fn fetch_topic_posting_context(
        &self,
        _topic_id: i64,
    ) -> Result<Option<TopicPostingContext>, ForumError> {
        Err(ForumError::Internal(
            "fetch_topic_posting_context not implemented in SurrealService".into(),
        ))
    }

    fn fetch_message_edit_data(
        &self,
        _topic_id: i64,
        _msg_id: i64,
    ) -> Result<Option<MessageEditData>, ForumError> {
        Err(ForumError::Internal(
            "editing messages is not supported in SurrealService".into(),
        ))
    }

    fn persist_post(
        &self,
        ctx: &ForumContext,
        submission: crate::services::PostSubmission,
    ) -> Result<PostedMessage, ForumError> {
        let board_id = self.ensure_board(ctx)?;
        let subject = if submission.subject.is_empty() {
            "(no subject)".to_string()
        } else {
            submission.subject
        };
        let body = submission.body;
        let author = ctx.user_info.name.clone();

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;

        // If no topic_id, create a topic first.
        let topic_id = if let Some(tid) = submission.topic_id {
            tid.to_string()
        } else {
            let topic = rt
                .block_on(surreal_create_topic(
                    &self.client,
                    &board_id,
                    &subject,
                    &author,
                ))
                .map_err(|e| ForumError::Internal(e.to_string()))?;
            topic.id.unwrap_or_else(|| "topic:new".into())
        };

        let post = rt
            .block_on(surreal_create_post_in_topic(
                &self.client,
                &topic_id,
                &board_id,
                &subject,
                &body,
                &author,
            ))
            .map_err(|e| ForumError::Internal(e.to_string()))?;

        let message_id = post
            .id
            .and_then(|id| id.split(':').last().and_then(|s| s.parse().ok()))
            .unwrap_or(0);
        let topic_numeric = topic_id
            .split(':')
            .last()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);

        Ok(PostedMessage {
            topic_id: topic_numeric,
            message_id,
        })
    }

    fn fetch_quote_content(&self, _msg_id: i64) -> Result<Option<QuoteContent>, ForumError> {
        Err(ForumError::Internal(
            "fetch_quote_content not implemented in SurrealService".into(),
        ))
    }

    fn send_announcement(
        &self,
        _topic_id: i64,
    ) -> Result<crate::services::AnnouncementResult, ForumError> {
        Ok(crate::services::AnnouncementResult { recipients: 0 })
    }

    fn store_attachment(&self, _upload: AttachmentUpload) -> Result<AttachmentRecord, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let id = Utc::now().timestamp_millis();
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        CREATE attachments CONTENT {
                            id: $id,
                            name: $name,
                            tmp_path: $tmp_path,
                            size: $size,
                            mime_type: $mime_type,
                            width: $width,
                            height: $height,
                            message_id: null,
                            approved: true,
                            created_at_ms: time::now()
                        } RETURN id, name, size, mime_type, width, height, message_id, approved;
                        "#,
                    )
                    .bind(("id", id))
                    .bind(("name", _upload.name.clone()))
                    .bind(("tmp_path", _upload.tmp_path.clone()))
                    .bind(("size", _upload.size))
                    .bind(("mime_type", _upload.mime_type.clone()))
                    .bind(("width", _upload.width))
                    .bind(("height", _upload.height))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<i64>,
            name: String,
            size: i64,
            mime_type: String,
            width: Option<i32>,
            height: Option<i32>,
            message_id: Option<i64>,
            approved: bool,
        }
        let row: Option<Row> = response.take(0).ok().and_then(|mut v: Vec<Row>| v.pop());
        row.map(|r| AttachmentRecord {
            id: r.id.unwrap_or(id),
            name: r.name,
            size: r.size,
            mime_type: r.mime_type,
            approved: r.approved,
            width: r.width,
            height: r.height,
            message_id: r.message_id,
        })
        .ok_or_else(|| ForumError::Internal("failed to store attachment".into()))
    }

    fn delete_attachment(&self, _id: i64) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query("DELETE attachments WHERE id = $id")
                .bind(("id", _id))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn list_message_attachments(&self, _msg_id: i64) -> Result<Vec<AttachmentRecord>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT id, name, size, mime_type, width, height, message_id, approved
                        FROM attachments WHERE message_id = $msg_id;
                        "#,
                    )
                    .bind(("msg_id", _msg_id))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<i64>,
            name: String,
            size: i64,
            mime_type: String,
            width: Option<i32>,
            height: Option<i32>,
            message_id: Option<i64>,
            approved: bool,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .map(|r| AttachmentRecord {
                id: r.id.unwrap_or(0),
                name: r.name,
                size: r.size,
                mime_type: r.mime_type,
                approved: r.approved,
                width: r.width,
                height: r.height,
                message_id: r.message_id,
            })
            .collect())
    }

    fn link_attachment_to_message(
        &self,
        _attachment_id: i64,
        _msg_id: i64,
    ) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query("UPDATE attachments SET message_id = $msg_id WHERE id = $id")
                .bind(("msg_id", _msg_id))
                .bind(("id", _attachment_id))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn current_attachment_dir(&self) -> Result<i64, ForumError> {
        Ok(0)
    }

    fn attachment_dir_usage(&self, _dir_id: i64) -> Result<(i64, i64), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query("SELECT count() as files, sum(size) as total FROM attachments;")
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            files: Option<i64>,
            total: Option<i64>,
        }
        let row: Option<Row> = response.take(0).ok().and_then(|mut v: Vec<Row>| v.pop());
        Ok((
            row.as_ref().and_then(|r| r.files).unwrap_or(0),
            row.and_then(|r| r.total).unwrap_or(0),
        ))
    }

    fn update_attachment_dir_usage(
        &self,
        _dir_id: i64,
        _size_delta: i64,
        _file_delta: i64,
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn save_draft_record(&self, _record: DraftStorage) -> Result<i64, ForumError> {
        Err(Self::unsupported("drafts"))
    }

    fn delete_draft(&self, _draft_id: i64) -> Result<(), ForumError> {
        Err(Self::unsupported("drafts"))
    }

    fn read_draft(&self, _draft_id: i64) -> Result<Option<DraftStorage>, ForumError> {
        Err(Self::unsupported("drafts"))
    }

    fn update_notify_pref(&self, _user_id: i64, _auto: bool) -> Result<NotifyPrefs, ForumError> {
        Ok(NotifyPrefs {
            msg_auto_notify: false,
        })
    }

    fn can_link_event(&self, _user_id: i64) -> Result<bool, ForumError> {
        Err(Self::unsupported("calendar"))
    }

    fn insert_event(&self, _event: CalendarEvent) -> Result<i64, ForumError> {
        Err(Self::unsupported("calendar"))
    }

    fn modify_event(&self, _event_id: i64, _event: CalendarEvent) -> Result<(), ForumError> {
        Err(Self::unsupported("calendar"))
    }

    fn create_poll(&self, _poll: PollData) -> Result<i64, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let poll_id = Utc::now().timestamp_millis();
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    CREATE polls CONTENT {
                        id: $id,
                        topic_id: $topic_id,
                        question: $question,
                        max_votes: $max_votes,
                        change_vote: $change_vote,
                        guest_vote: $guest_vote,
                        created_at_ms: time::now()
                    };
                    "#,
                )
                .bind(("id", poll_id))
                .bind(("topic_id", _poll.topic_id))
                .bind(("question", _poll.question.clone()))
                .bind(("max_votes", _poll.max_votes))
                .bind(("change_vote", _poll.change_vote))
                .bind(("guest_vote", _poll.guest_vote))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;

        for option in &_poll.options {
            rt.block_on(async {
                self.client
                    .query(
                        r#"
                        CREATE poll_options CONTENT {
                            poll_id: $poll_id,
                            option_id: $option_id,
                            label: $label,
                            votes: $votes
                        };
                        "#,
                    )
                    .bind(("poll_id", poll_id))
                    .bind(("option_id", option.id))
                    .bind(("label", option.label.clone()))
                    .bind(("votes", option.votes))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        }

        Ok(poll_id)
    }

    fn remove_poll(&self, _poll_id: i64) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query("DELETE poll_options WHERE poll_id = $id; DELETE polls WHERE id = $id;")
                .bind(("id", _poll_id))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn lock_poll(&self, _poll_id: i64, _lock: bool) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query("UPDATE polls SET locked = $locked WHERE id = $id;")
                .bind(("locked", _lock))
                .bind(("id", _poll_id))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn cast_vote(
        &self,
        _poll_id: i64,
        _member_id: i64,
        _options: &[i64],
    ) -> Result<(), ForumError> {
        if _options.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        for opt in _options {
            rt.block_on(async {
                self.client
                    .query(
                        r#"
                        UPDATE poll_options SET votes += 1
                        WHERE poll_id = $poll_id AND option_id = $option_id;
                        "#,
                    )
                    .bind(("poll_id", _poll_id))
                    .bind(("option_id", *opt))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    fn fetch_topic_messages(
        &self,
        topic_id: i64,
        _start: i64,
        _limit: i64,
    ) -> Result<Vec<MessageData>, ForumError> {
        let tid = topic_id.to_string();
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let posts = rt
            .block_on(surreal_list_posts_for_topic(&self.client, &tid))
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(posts
            .into_iter()
            .map(|p| MessageData {
                id: p
                    .id
                    .as_deref()
                    .and_then(|id| id.split(':').last())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                topic_id,
                body: p.body,
                subject: p.subject,
                member_id: 0,
                approved: true,
            })
            .collect())
    }

    fn increment_topic_views(&self, _topic_id: i64) -> Result<(), ForumError> {
        Ok(())
    }

    fn list_membergroups(&self) -> Result<Vec<MembergroupSummary>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT id, name, description
                        FROM membergroups;
                        "#,
                    )
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<i64>,
            name: Option<String>,
            description: Option<String>,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .map(|r| MembergroupSummary {
                id: r.id.unwrap_or(0),
                name: r.name.unwrap_or_default(),
                num_members: 0,
                color: None,
                is_post_group: false,
            })
            .collect())
    }

    fn get_membergroup(&self, _group_id: i64) -> Result<Option<MembergroupData>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT id, name, description, type
                        FROM membergroups WHERE id = $id LIMIT 1;
                        "#,
                    )
                    .bind(("id", _group_id))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<i64>,
            name: Option<String>,
            description: Option<String>,
            r#type: Option<i32>,
            color: Option<String>,
            hidden: Option<bool>,
            min_posts: Option<i64>,
        }
        let row: Option<Row> = response.take(0).ok().and_then(|mut v: Vec<Row>| v.pop());
        Ok(row.map(|r| MembergroupData {
            id: r.id,
            name: r.name.unwrap_or_default(),
            description: r.description.unwrap_or_default(),
            inherits_from: None,
            allowed_boards: Vec::new(),
            color: r.color,
            is_post_group: false,
            min_posts: r.min_posts.unwrap_or(0),
            group_type: r.r#type.unwrap_or(0),
            hidden: r.hidden.unwrap_or(false),
            icons: None,
            is_protected: false,
        }))
    }

    fn save_membergroup(&self, _group: MembergroupData) -> Result<i64, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let id = _group.id.unwrap_or_else(|| Utc::now().timestamp_millis());
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    UPDATE membergroups SET
                        name = $name,
                        description = $description,
                        type = $type
                    WHERE id = $id;
                    "#,
                )
                .bind(("name", _group.name.clone()))
                .bind(("description", _group.description.clone()))
                .bind(("type", _group.group_type.clone()))
                .bind(("id", id))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(id)
    }

    fn list_group_members(&self, _group_id: i64) -> Result<Vec<GroupMember>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT member_id, is_primary, name
                        FROM group_members
                        WHERE group_id = $group_id;
                        "#,
                    )
                    .bind(("group_id", _group_id))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            member_id: Option<i64>,
            is_primary: Option<bool>,
            name: Option<String>,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .filter_map(|r| {
                r.member_id.map(|mid| GroupMember {
                    id: mid,
                    name: r.name.unwrap_or_default(),
                    primary: r.is_primary.unwrap_or(false),
                })
            })
            .collect())
    }

    fn remove_members_from_group(
        &self,
        _group_id: i64,
        _members: &[i64],
    ) -> Result<(), ForumError> {
        if _members.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    DELETE group_members
                    WHERE group_id = $group_id AND member_id IN $members;
                    "#,
                )
                .bind(("group_id", _group_id))
                .bind(("members", _members.to_vec()))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_membergroup_settings(&self) -> Result<MembergroupSettings, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT show_group_key
                        FROM membergroup_settings
                        LIMIT 1;
                        "#,
                    )
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            show_group_key: Option<bool>,
        }
        let row: Option<Row> = response.take(0).ok().and_then(|mut v: Vec<Row>| v.pop());
        Ok(MembergroupSettings {
            show_group_key: row.and_then(|r| r.show_group_key).unwrap_or(false),
        })
    }

    fn save_membergroup_settings(&self, _settings: MembergroupSettings) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    UPDATE membergroup_settings SET
                        show_group_key = $show_group_key;
                    "#,
                )
                .bind(("show_group_key", _settings.show_group_key))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn delete_membergroups(&self, _group_ids: &[i64]) -> Result<(), ForumError> {
        if _group_ids.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    DELETE membergroups WHERE id IN $ids;
                    DELETE group_members WHERE group_id IN $ids;
                    "#,
                )
                .bind(("ids", _group_ids.to_vec()))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn remove_members_from_groups(
        &self,
        _member_ids: &[i64],
        _group_ids: Option<&[i64]>,
    ) -> Result<(), ForumError> {
        if _member_ids.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let ids = _member_ids.to_vec();
        let mut query = String::from("DELETE group_members WHERE member_id IN $members");
        if let Some(groups) = _group_ids {
            query.push_str(" AND group_id IN $groups");
            rt.block_on(async {
                self.client
                    .query(query)
                    .bind(("members", ids))
                    .bind(("groups", groups.to_vec()))
                    .await
            })
        } else {
            rt.block_on(async { self.client.query(query).bind(("members", ids)).await })
        }
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn add_members_to_group(
        &self,
        _member_ids: &[i64],
        _group_id: i64,
        _assign_type: GroupAssignType,
    ) -> Result<(), ForumError> {
        if _member_ids.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        for member in _member_ids {
            rt.block_on(async {
                self.client
                    .query(
                        r#"
                        CREATE group_members CONTENT {
                            group_id: $group_id,
                            member_id: $member_id,
                            is_primary: false
                        };
                        "#,
                    )
                    .bind(("group_id", _group_id))
                    .bind(("member_id", *member))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    fn list_membergroups_detailed(
        &self,
        _group_type: MembergroupListType,
    ) -> Result<Vec<MembergroupListEntry>, ForumError> {
        let summaries = self.list_membergroups()?;
        Ok(summaries
            .into_iter()
            .map(|s| MembergroupListEntry {
                id: s.id,
                name: s.name,
                description: String::new(),
                min_posts: 0,
                color: s.color.clone(),
                group_type: 0,
                num_members: s.num_members,
                moderators: Vec::new(),
                icons: None,
                can_moderate: false,
                hidden: s.is_post_group,
            })
            .collect())
    }

    fn groups_with_permissions(
        &self,
        _group_permissions: &[String],
        _board_permissions: &[String],
        _profile_id: i64,
    ) -> Result<std::collections::HashMap<String, PermissionSnapshot>, ForumError> {
        Err(Self::unsupported("permissions"))
    }

    fn permission_groups(&self) -> Result<Vec<PermissionGroupContext>, ForumError> {
        Ok(Vec::new())
    }

    fn permission_profiles(&self) -> Result<Vec<PermissionProfile>, ForumError> {
        Ok(Vec::new())
    }

    fn ungrouped_member_count(&self) -> Result<i64, ForumError> {
        Ok(0)
    }

    fn get_member_record(&self, _member_id: i64) -> Result<Option<MemberRecord>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let id_str = format!("users:{}", _member_id);
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT meta::id(id) as id, name, role, permissions
                        FROM $id
                        LIMIT 1;
                        "#,
                    )
                    .bind(("id", id_str))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<String>,
            name: String,
            _role: Option<String>,
            _permissions: Option<Vec<String>>,
        }
        let row: Option<Row> = response.take(0).ok().and_then(|mut v: Vec<Row>| v.pop());
        Ok(row.map(|row| MemberRecord {
            id: row
                .id
                .as_deref()
                .and_then(|id| id.split(':').last())
                .and_then(|s| s.parse().ok())
                .unwrap_or(_member_id),
            name: row.name,
            primary_group: None,
            additional_groups: Vec::new(),
            password: String::new(),
            warning: 0,
        }))
    }

    fn update_member_groups(
        &self,
        _member_id: i64,
        _primary_group: Option<i64>,
        _additional_groups: &[i64],
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn list_all_membergroups(&self) -> Result<Vec<MembergroupData>, ForumError> {
        Ok(Vec::new())
    }

    fn list_members(&self) -> Result<Vec<MemberRecord>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT meta::id(id) as id, name, role, permissions
                        FROM users;
                        "#,
                    )
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<String>,
            name: String,
            _role: Option<String>,
            _permissions: Option<Vec<String>>,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .map(|row| MemberRecord {
                id: row
                    .id
                    .as_deref()
                    .and_then(|id| id.split(':').last())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                name: row.name,
                primary_group: None,
                additional_groups: Vec::new(),
                password: String::new(),
                warning: 0,
            })
            .collect())
    }

    fn delete_member(&self, _member_id: i64) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let id_str = format!("users:{}", _member_id);
        rt.block_on(async { self.client.query("DELETE $id").bind(("id", id_str)).await })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn list_board_access(&self) -> Result<Vec<BoardAccessEntry>, ForumError> {
        Ok(Vec::new())
    }

    fn set_board_access(&self, _board_id: i64, _groups: &[i64]) -> Result<(), ForumError> {
        Ok(())
    }

    fn fetch_alert_prefs(
        &self,
        _members: &[i64],
        _prefs: Option<&[String]>,
    ) -> Result<std::collections::HashMap<i64, std::collections::HashMap<String, i32>>, ForumError>
    {
        if _members.is_empty() {
            return Ok(std::collections::HashMap::new());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT member_id, prefs FROM alert_prefs
                        WHERE member_id IN $member_ids;
                        "#,
                    )
                    .bind(("member_ids", _members.to_vec()))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            member_id: Option<i64>,
            prefs: Option<std::collections::HashMap<String, i32>>,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        let mut map = std::collections::HashMap::new();
        for row in rows {
            if let Some(member_id) = row.member_id {
                if let Some(prefs_map) = row.prefs {
                    let filtered = if let Some(only) = _prefs {
                        prefs_map
                            .into_iter()
                            .filter(|(k, _)| only.contains(k))
                            .collect()
                    } else {
                        prefs_map
                    };
                    map.insert(member_id, filtered);
                }
            }
        }
        Ok(map)
    }

    fn set_alert_prefs(&self, _member_id: i64, _prefs: &[(String, i32)]) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let prefs_map: std::collections::HashMap<String, i32> = _prefs.iter().cloned().collect();
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    UPDATE alert_prefs SET prefs = $prefs WHERE member_id = $member_id;
                    IF none THEN (
                        CREATE alert_prefs CONTENT { member_id: $member_id, prefs: $prefs };
                    );
                    "#,
                )
                .bind(("member_id", _member_id))
                .bind(("prefs", prefs_map))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn delete_alert_prefs(&self, _member_id: i64, _prefs: &[String]) -> Result<(), ForumError> {
        if _prefs.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let prefs = _prefs.to_vec();
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    LET existing = (SELECT prefs FROM alert_prefs WHERE member_id = $member_id LIMIT 1);
                    IF count(existing) > 0 THEN (
                        UPDATE alert_prefs SET prefs = object::remove(prefs, $remove_keys)
                        WHERE member_id = $member_id;
                    );
                    "#,
                )
                .bind(("member_id", _member_id))
                .bind(("remove_keys", prefs))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn get_member_email(&self, _member_id: i64) -> Result<Option<String>, ForumError> {
        Ok(None)
    }

    fn notification_secret(&self) -> Result<String, ForumError> {
        Ok(String::new())
    }

    fn general_permissions(&self, _group_ids: &[i64]) -> Result<Vec<PermissionChange>, ForumError> {
        Ok(Vec::new())
    }

    fn board_permissions(
        &self,
        _board_id: i64,
        _group_ids: &[i64],
    ) -> Result<Vec<PermissionChange>, ForumError> {
        Ok(Vec::new())
    }

    fn spider_group_id(&self) -> Option<i64> {
        None
    }

    fn settings_last_updated(&self) -> i64 {
        Utc::now().timestamp()
    }

    fn list_ban_rules(&self) -> Result<Vec<BanRule>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT id, reason, expires_at_ms
                        FROM ban_rules;
                        "#,
                    )
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<i64>,
            reason: Option<String>,
            expires_at_ms: Option<i64>,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .map(|r| BanRule {
                id: r.id.unwrap_or(0),
                reason: r.reason,
                expires_at: r
                    .expires_at_ms
                    .and_then(|ms| Utc.timestamp_millis_opt(ms).single()),
                conditions: Vec::new(),
            })
            .collect())
    }

    fn save_ban_rule(&self, _rule: BanRule) -> Result<i64, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let rule_id = if _rule.id == 0 {
            Utc::now().timestamp_millis()
        } else {
            _rule.id
        };
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    UPDATE ban_rules SET
                        reason = $reason,
                        expires_at_ms = $expires
                    WHERE id = $id;
                    "#,
                )
                .bind(("reason", _rule.reason.clone()))
                .bind(("expires", _rule.expires_at.map(|dt| dt.timestamp_millis())))
                .bind(("id", rule_id))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(rule_id)
    }

    fn delete_ban_rule(&self, _rule_id: i64) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query("DELETE ban_rules WHERE id = $id;")
                .bind(("id", _rule_id))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn ban_logs(&self) -> Result<Vec<BanLogEntry>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT id, ban_id, email, hit_at_ms
                        FROM ban_logs;
                        "#,
                    )
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<i64>,
            ban_id: Option<i64>,
            email: Option<String>,
            hit_at_ms: Option<i64>,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .map(|r| BanLogEntry {
                id: r.id.unwrap_or(0),
                rule_id: r.ban_id.unwrap_or(0),
                email: r.email,
                timestamp: r
                    .hit_at_ms
                    .and_then(|ms| Utc.timestamp_millis_opt(ms).single())
                    .unwrap_or_else(Utc::now),
                member_id: None,
            })
            .collect())
    }

    fn record_ban_hit(&self, _bans: &[i64], _email: Option<&str>) -> Result<(), ForumError> {
        if _bans.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        for ban_id in _bans {
            rt.block_on(async {
                self.client
                    .query(
                        r#"
                        CREATE ban_logs CONTENT {
                            ban_id: $ban_id,
                            email: $email,
                            hit_at_ms: time::now()
                        };
                        "#,
                    )
                    .bind(("ban_id", *ban_id))
                    .bind(("email", _email.unwrap_or_default().to_string()))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        }
        Ok(())
    }

    fn find_member_by_name(&self, _name: &str) -> Result<Option<MemberRecord>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let name = _name.to_owned();
        let user = rt
            .block_on(get_user_by_name(&self.client, &name))
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(user.map(|u| MemberRecord {
            id: u
                .id
                .as_deref()
                .and_then(|id| id.split(':').last())
                .and_then(|s| s.parse().ok())
                .unwrap_or(0),
            name: u.name,
            primary_group: None,
            additional_groups: Vec::new(),
            password: String::new(),
            warning: 0,
        }))
    }

    fn find_members_by_name(&self, _names: &[String]) -> Result<Vec<MemberRecord>, ForumError> {
        let mut members = Vec::new();
        for name in _names {
            if let Ok(Some(rec)) = self.find_member_by_name(name) {
                members.push(rec);
            }
        }
        Ok(members)
    }

    fn cleanup_pm_recipients(&self, _member_ids: &[i64]) -> Result<(), ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn cleanup_pm_ignore_lists(&self, _member_ids: &[i64]) -> Result<(), ForumError> {
        Ok(())
    }

    fn get_pm_ignore_list(&self, _member_id: i64) -> Result<Vec<i64>, ForumError> {
        Ok(Vec::new())
    }

    fn set_pm_ignore_list(&self, _member_id: i64, _members: &[i64]) -> Result<(), ForumError> {
        Ok(())
    }

    fn get_buddy_list(&self, _member_id: i64) -> Result<Vec<i64>, ForumError> {
        Ok(Vec::new())
    }

    fn get_pm_preferences(&self, _member_id: i64) -> Result<PmPreferenceState, ForumError> {
        Ok(PmPreferenceState::default())
    }

    fn save_pm_preferences(
        &self,
        _member_id: i64,
        _prefs: &PmPreferenceState,
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn record_pm_sent(
        &self,
        _sender_id: i64,
        _timestamp: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), ForumError> {
        // Stored implicitly via send_personal_message (Sent folder), nothing extra required.
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    CREATE pm_send_log CONTENT {
                        sender_id: $sender_id,
                        created_at_ms: $created_at
                    };
                    "#,
                )
                .bind(("sender_id", _sender_id))
                .bind(("created_at", _timestamp.timestamp_millis()))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn count_pm_sent_since(
        &self,
        _sender_id: i64,
        _since: chrono::DateTime<chrono::Utc>,
    ) -> Result<usize, ForumError> {
        let since_ms = _since.timestamp_millis();
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT count() as total
                        FROM personal_messages
                        WHERE owner_id = $owner_id
                          AND folder = "Sent"
                          AND created_at_ms >= $since_ms;
                        "#,
                    )
                    .bind(("owner_id", _sender_id))
                    .bind(("since_ms", since_ms))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct CountRow {
            total: Option<usize>,
        }
        let row: Option<CountRow> = response
            .take(0)
            .ok()
            .and_then(|mut v: Vec<CountRow>| v.pop());
        Ok(row.and_then(|c| c.total).unwrap_or(0))
    }

    fn log_action(
        &self,
        _action: &str,
        _member_id: Option<i64>,
        _details: &Value,
    ) -> Result<(), ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let action = _action.to_string();
        let details = _details.clone();
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    CREATE action_logs CONTENT {
                        action: $action,
                        member_id: $member_id,
                        details: $details,
                        created_at_ms: time::now()
                    };
                    "#,
                )
                .bind(("action", action))
                .bind(("member_id", _member_id))
                .bind(("details", details))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn list_action_logs(&self) -> Result<Vec<ActionLogEntry>, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT action, member_id, details, created_at_ms
                        FROM action_logs
                        ORDER BY created_at_ms DESC
                        LIMIT 200;
                        "#,
                    )
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            id: Option<String>,
            action: Option<String>,
            member_id: Option<i64>,
            details: Option<Value>,
            created_at_ms: Option<i64>,
        }
        let rows: Vec<Row> = response.take(0).unwrap_or_default();
        Ok(rows
            .into_iter()
            .map(|r| ActionLogEntry {
                id: r
                    .id
                    .as_deref()
                    .and_then(|id| id.split(':').last())
                    .and_then(|s| s.parse().ok())
                    .unwrap_or(0),
                action: r.action.unwrap_or_default(),
                member_id: r.member_id,
                details: r.details.unwrap_or(Value::Null),
                timestamp: r
                    .created_at_ms
                    .and_then(|ms| Utc.timestamp_millis_opt(ms).single())
                    .unwrap_or_else(Utc::now),
            })
            .collect())
    }

    fn clean_expired_bans(&self) -> Result<usize, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        DELETE ban_rules
                        WHERE expires_at_ms IS NOT NONE AND expires_at_ms < time::now()
                        RETURN count();
                        "#,
                    )
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct Row {
            count: Option<usize>,
        }
        let row: Option<Row> = response.take(0).ok().and_then(|mut v: Vec<Row>| v.pop());
        Ok(row.and_then(|r| r.count).unwrap_or(0))
    }

    fn save_pm_draft(&self, _draft: PmDraftRecord) -> Result<i64, ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn delete_pm_draft(&self, _owner_id: i64, _draft_id: i64) -> Result<(), ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn list_pm_drafts(
        &self,
        _owner_id: i64,
        _start: usize,
        _limit: usize,
    ) -> Result<Vec<PmDraftRecord>, ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn read_pm_draft(
        &self,
        _owner_id: i64,
        _draft_id: i64,
    ) -> Result<Option<PmDraftRecord>, ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn personal_message_overview(
        &self,
        _user_id: i64,
    ) -> Result<PersonalMessageOverview, ForumError> {
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT
                            count() as total,
                            count(is_read = false) as unread
                        FROM personal_messages
                        WHERE owner_id = $owner_id;
                        "#,
                    )
                    .bind(("owner_id", _user_id))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct CountRow {
            total: Option<usize>,
            unread: Option<usize>,
        }
        let row: Option<CountRow> = response
            .take(0)
            .ok()
            .and_then(|mut v: Vec<CountRow>| v.pop());
        Ok(PersonalMessageOverview {
            limit: None,
            total: row.as_ref().and_then(|c| c.total).unwrap_or(0),
            unread: row.and_then(|c| c.unread).unwrap_or(0),
        })
    }

    fn personal_message_labels(
        &self,
        _user_id: i64,
    ) -> Result<Vec<PersonalMessageLabel>, ForumError> {
        Ok(Vec::new())
    }

    fn personal_message_page(
        &self,
        _user_id: i64,
        _folder: PersonalMessageFolder,
        _label: Option<i64>,
        _start: usize,
        _limit: usize,
    ) -> Result<PersonalMessagePage, ForumError> {
        #[derive(Deserialize)]
        struct PmRow {
            pm_id: i64,
            _owner_id: i64,
            sender_id: i64,
            sender_name: String,
            subject: String,
            body: String,
            is_read: bool,
            _folder: String,
            created_at_ms: i64,
            recipients: Option<Vec<i64>>,
        }

        let folder = match _folder {
            PersonalMessageFolder::Inbox => "Inbox",
            PersonalMessageFolder::Sent => "Sent",
        };

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;

        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT pm_id, owner_id, sender_id, sender_name, subject, body, is_read, folder, created_at_ms, recipients
                        FROM personal_messages
                        WHERE owner_id = $owner_id AND folder = $folder
                        ORDER BY created_at_ms DESC
                        LIMIT $limit START $start;
                        "#,
                    )
                    .bind(("owner_id", _user_id))
                    .bind(("folder", folder))
                    .bind(("limit", _limit as i64))
                    .bind(("start", _start as i64))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;

        let rows: Vec<PmRow> = response.take(0).unwrap_or_default();

        let messages = rows
            .into_iter()
            .map(|row| {
                let sent_at = Self::parse_ts(row.created_at_ms);
                PersonalMessageSummary {
                    id: row.pm_id,
                    subject: row.subject,
                    body_preview: row.body.chars().take(120).collect(),
                    sender_id: row.sender_id,
                    sender_name: row.sender_name,
                    sent_at,
                    is_read: row.is_read,
                    recipients: row
                        .recipients
                        .unwrap_or_default()
                        .into_iter()
                        .map(|id| PersonalMessagePeer {
                            member_id: id,
                            name: String::new(),
                        })
                        .collect(),
                    labels: Vec::new(),
                }
            })
            .collect();

        // counts
        let mut counts = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT
                            count() as total,
                            count(is_read = false) as unread
                        FROM personal_messages
                        WHERE owner_id = $owner_id AND folder = $folder;
                        "#,
                    )
                    .bind(("owner_id", _user_id))
                    .bind(("folder", folder))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;

        #[derive(Deserialize)]
        struct CountRow {
            total: Option<usize>,
            unread: Option<usize>,
        }
        let count_row: Option<CountRow> =
            counts.take(0).ok().and_then(|mut v: Vec<CountRow>| v.pop());

        Ok(PersonalMessagePage {
            start: _start,
            total: count_row.as_ref().and_then(|c| c.total).unwrap_or(0),
            unread: count_row.as_ref().and_then(|c| c.unread).unwrap_or(0),
            messages,
        })
    }

    fn personal_message_popup(
        &self,
        _user_id: i64,
        _limit: usize,
    ) -> Result<Vec<PersonalMessageSummary>, ForumError> {
        let page =
            self.personal_message_page(_user_id, PersonalMessageFolder::Inbox, None, 0, _limit)?;
        Ok(page.messages)
    }

    fn personal_message_detail(
        &self,
        _user_id: i64,
        _pm_id: i64,
    ) -> Result<Option<PersonalMessageDetail>, ForumError> {
        #[derive(Deserialize)]
        struct PmRow {
            pm_id: i64,
            _owner_id: i64,
            sender_id: i64,
            sender_name: String,
            subject: String,
            body: String,
            is_read: bool,
            created_at_ms: i64,
            recipients: Option<Vec<i64>>,
        }

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;

        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        SELECT pm_id, owner_id, sender_id, sender_name, subject, body, is_read, created_at_ms, recipients
                        FROM personal_messages
                        WHERE owner_id = $owner_id AND pm_id = $pm_id
                        LIMIT 1;
                        "#,
                    )
                    .bind(("owner_id", _user_id))
                    .bind(("pm_id", _pm_id))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;

        let row: Option<PmRow> = response.take(0).ok().and_then(|mut v: Vec<PmRow>| v.pop());
        Ok(row.map(|row| PersonalMessageDetail {
            id: row.pm_id,
            subject: row.subject,
            body: row.body,
            sender_id: row.sender_id,
            sender_name: row.sender_name,
            sent_at: Self::parse_ts(row.created_at_ms),
            recipients: row
                .recipients
                .unwrap_or_default()
                .into_iter()
                .map(|id| PersonalMessagePeer {
                    member_id: id,
                    name: String::new(),
                })
                .collect(),
            labels: Vec::new(),
            is_read: row.is_read,
        }))
    }

    fn send_personal_message(
        &self,
        request: SendPersonalMessage,
    ) -> Result<PersonalMessageSendResult, ForumError> {
        if request.to.is_empty() && request.bcc.is_empty() {
            return Err(ForumError::Internal("no recipients provided".into()));
        }
        let recipients: Vec<i64> = request
            .to
            .iter()
            .chain(request.bcc.iter())
            .cloned()
            .collect();
        let pm_id = Utc::now().timestamp_millis();
        let created_at_ms = pm_id;

        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;

        for recipient in &recipients {
            rt.block_on(async {
                self.client
                    .query(
                        r#"
                        CREATE personal_messages CONTENT {
                            pm_id: $pm_id,
                            owner_id: $owner_id,
                            sender_id: $sender_id,
                            sender_name: $sender_name,
                            subject: $subject,
                            body: $body,
                            is_read: false,
                            folder: "Inbox",
                            created_at_ms: $created_at_ms,
                            recipients: $recipients
                        };
                        "#,
                    )
                    .bind(("pm_id", pm_id))
                    .bind(("owner_id", *recipient))
                    .bind(("sender_id", request.sender_id))
                    .bind(("sender_name", request.sender_name.clone()))
                    .bind(("subject", request.subject.clone()))
                    .bind(("body", request.body.clone()))
                    .bind(("created_at_ms", created_at_ms))
                    .bind(("recipients", recipients.clone()))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        }

        rt.block_on(async {
            self.client
                .query(
                    r#"
                    CREATE personal_messages CONTENT {
                        pm_id: $pm_id,
                        owner_id: $owner_id,
                        sender_id: $sender_id,
                        sender_name: $sender_name,
                        subject: $subject,
                        body: $body,
                        is_read: true,
                        folder: "Sent",
                        created_at_ms: $created_at_ms,
                        recipients: $recipients
                    };
                    "#,
                )
                .bind(("pm_id", pm_id))
                .bind(("owner_id", request.sender_id))
                .bind(("sender_id", request.sender_id))
                .bind(("sender_name", request.sender_name.clone()))
                .bind(("subject", request.subject.clone()))
                .bind(("body", request.body.clone()))
                .bind(("created_at_ms", created_at_ms))
                .bind(("recipients", recipients.clone()))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;

        Ok(PersonalMessageSendResult {
            id: pm_id,
            recipient_ids: recipients,
        })
    }

    fn delete_personal_messages(
        &self,
        _user_id: i64,
        _folder: PersonalMessageFolder,
        _ids: &[i64],
    ) -> Result<(), ForumError> {
        if _ids.is_empty() {
            return Ok(());
        }
        let folder = match _folder {
            PersonalMessageFolder::Inbox => "Inbox",
            PersonalMessageFolder::Sent => "Sent",
        };
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    DELETE personal_messages
                    WHERE owner_id = $owner_id
                      AND folder = $folder
                      AND pm_id IN $ids;
                    "#,
                )
                .bind(("owner_id", _user_id))
                .bind(("folder", folder))
                .bind(("ids", _ids.to_vec()))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn mark_personal_messages(
        &self,
        _user_id: i64,
        _ids: &[i64],
        _read: bool,
    ) -> Result<(), ForumError> {
        if _ids.is_empty() {
            return Ok(());
        }
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        rt.block_on(async {
            self.client
                .query(
                    r#"
                    UPDATE personal_messages SET is_read = $read
                    WHERE owner_id = $owner_id
                      AND pm_id IN $ids;
                    "#,
                )
                .bind(("owner_id", _user_id))
                .bind(("ids", _ids.to_vec()))
                .bind(("read", _read))
                .await
        })
        .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(())
    }

    fn prune_personal_messages(&self, _user_id: i64, _days: i64) -> Result<usize, ForumError> {
        let cutoff = Utc::now() - chrono::Duration::days(_days);
        let cutoff_ms = cutoff.timestamp_millis();
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        DELETE personal_messages
                        WHERE owner_id = $owner_id
                          AND created_at_ms < $cutoff_ms
                        RETURN count();
                        "#,
                    )
                    .bind(("owner_id", _user_id))
                    .bind(("cutoff_ms", cutoff_ms))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct CountRow {
            count: Option<usize>,
        }
        let count: Option<CountRow> = response
            .take(0)
            .ok()
            .and_then(|mut v: Vec<CountRow>| v.pop());
        Ok(count.and_then(|c| c.count).unwrap_or(0))
    }

    fn clear_personal_messages(
        &self,
        _user_id: i64,
        _folder: PersonalMessageFolder,
    ) -> Result<usize, ForumError> {
        let folder = match _folder {
            PersonalMessageFolder::Inbox => "Inbox",
            PersonalMessageFolder::Sent => "Sent",
        };
        let rt = tokio::runtime::Runtime::new()
            .map_err(|e| ForumError::Internal(format!("runtime init failed: {e}")))?;
        let mut response = rt
            .block_on(async {
                self.client
                    .query(
                        r#"
                        DELETE personal_messages
                        WHERE owner_id = $owner_id
                          AND folder = $folder
                        RETURN count();
                        "#,
                    )
                    .bind(("owner_id", _user_id))
                    .bind(("folder", folder))
                    .await
            })
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        #[derive(Deserialize)]
        struct CountRow {
            count: Option<usize>,
        }
        let count: Option<CountRow> = response
            .take(0)
            .ok()
            .and_then(|mut v: Vec<CountRow>| v.pop());
        Ok(count.and_then(|c| c.count).unwrap_or(0))
    }

    fn create_pm_label(&self, _user_id: i64, _name: &str) -> Result<i64, ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn rename_pm_label(
        &self,
        _user_id: i64,
        _label_id: i64,
        _name: &str,
    ) -> Result<(), ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn delete_pm_labels(&self, _user_id: i64, _labels: &[i64]) -> Result<(), ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn label_personal_messages(
        &self,
        _user_id: i64,
        _ids: &[i64],
        _label_id: i64,
        _add: bool,
    ) -> Result<(), ForumError> {
        Err(Self::unsupported("personal messages"))
    }

    fn search_personal_messages(
        &self,
        _user_id: i64,
        _query: &PersonalMessageSearchQuery,
    ) -> Result<Vec<PersonalMessageSummary>, ForumError> {
        let page =
            self.personal_message_page(_user_id, PersonalMessageFolder::Inbox, None, 0, 200)?;
        let text = _query.text.to_lowercase();
        let filtered = page
            .messages
            .into_iter()
            .filter(|msg| {
                msg.subject.to_lowercase().contains(&text)
                    || msg.body_preview.to_lowercase().contains(&text)
            })
            .collect();
        Ok(filtered)
    }
}
