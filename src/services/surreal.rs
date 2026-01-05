use crate::services::{
    ActionLogEntry, AttachmentRecord, AttachmentUpload, BanLogEntry, BanRule, BoardAccessEntry,
    BoardListOptions, BoardSummary, CalendarEvent, DraftStorage, ForumContext, ForumError,
    ForumService, GroupAssignType, GroupMember, MemberRecord, MembergroupData,
    MembergroupListEntry, MembergroupListType, MembergroupSettings, MembergroupSummary,
    MessageData, MessageEditData, NotifyPrefs, PermissionChange, PermissionGroupContext,
    PermissionProfile, PermissionSnapshot, PersonalMessageDetail, PersonalMessageFolder,
    PersonalMessageLabel, PersonalMessageOverview, PersonalMessagePage, PersonalMessageSendResult,
    PersonalMessageSummary, PersonalMessageSearchQuery, PollData, PostedMessage, PmDraftRecord,
    PmPreferenceState, QuoteContent, SendPersonalMessage, SessionCheckMode, TopicPostingContext,
};
use crate::surreal::{
    SurrealClient, create_board as surreal_create_board,
    create_post_in_topic as surreal_create_post_in_topic, create_topic as surreal_create_topic,
    list_boards as surreal_list_boards, list_posts_for_topic as surreal_list_posts_for_topic,
};
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
            .block_on(surreal_create_board(&self.client, "General", Some("Default board")))
            .map_err(|e| ForumError::Internal(e.to_string()))?;
        Ok(created.id.unwrap_or_else(|| "board:default".into()))
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
        Ok(NotifyPrefs { msg_auto_notify: false })
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
            .map(|(idx, b)| BoardSummary { id: idx as i64 + 1, name: b.name })
            .collect())
    }

    fn check_session(&self, _ctx: &ForumContext, _mode: SessionCheckMode) -> Result<(), ForumError> {
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
        Ok(None)
    }

    fn fetch_topic_posting_context(
        &self,
        _topic_id: i64,
    ) -> Result<Option<TopicPostingContext>, ForumError> {
        Ok(None)
    }

    fn fetch_message_edit_data(
        &self,
        _topic_id: i64,
        _msg_id: i64,
    ) -> Result<Option<MessageEditData>, ForumError> {
        Ok(None)
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
        Ok(None)
    }

    fn send_announcement(&self, _topic_id: i64) -> Result<crate::services::AnnouncementResult, ForumError> {
        Ok(crate::services::AnnouncementResult { recipients: 0 })
    }

    fn store_attachment(&self, _upload: AttachmentUpload) -> Result<AttachmentRecord, ForumError> {
        Err(ForumError::Internal("attachments not supported in SurrealService".into()))
    }

    fn delete_attachment(&self, _id: i64) -> Result<(), ForumError> {
        Err(ForumError::Internal("attachments not supported in SurrealService".into()))
    }

    fn list_message_attachments(&self, _msg_id: i64) -> Result<Vec<AttachmentRecord>, ForumError> {
        Ok(Vec::new())
    }

    fn link_attachment_to_message(&self, _attachment_id: i64, _msg_id: i64) -> Result<(), ForumError> {
        Ok(())
    }

    fn current_attachment_dir(&self) -> Result<i64, ForumError> {
        Ok(0)
    }

    fn attachment_dir_usage(&self, _dir_id: i64) -> Result<(i64, i64), ForumError> {
        Ok((0, 0))
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
        Err(ForumError::Internal("drafts not supported in SurrealService".into()))
    }

    fn delete_draft(&self, _draft_id: i64) -> Result<(), ForumError> {
        Ok(())
    }

    fn read_draft(&self, _draft_id: i64) -> Result<Option<DraftStorage>, ForumError> {
        Ok(None)
    }

    fn update_notify_pref(&self, _user_id: i64, _auto: bool) -> Result<NotifyPrefs, ForumError> {
        Ok(NotifyPrefs { msg_auto_notify: false })
    }

    fn can_link_event(&self, _user_id: i64) -> Result<bool, ForumError> {
        Ok(false)
    }

    fn insert_event(&self, _event: CalendarEvent) -> Result<i64, ForumError> {
        Err(ForumError::Internal("calendar not supported in SurrealService".into()))
    }

    fn modify_event(&self, _event_id: i64, _event: CalendarEvent) -> Result<(), ForumError> {
        Ok(())
    }

    fn create_poll(&self, _poll: PollData) -> Result<i64, ForumError> {
        Err(ForumError::Internal("polls not supported in SurrealService".into()))
    }

    fn remove_poll(&self, _poll_id: i64) -> Result<(), ForumError> {
        Ok(())
    }

    fn lock_poll(&self, _poll_id: i64, _lock: bool) -> Result<(), ForumError> {
        Ok(())
    }

    fn cast_vote(&self, _poll_id: i64, _member_id: i64, _options: &[i64]) -> Result<(), ForumError> {
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
        Ok(Vec::new())
    }

    fn get_membergroup(&self, _group_id: i64) -> Result<Option<MembergroupData>, ForumError> {
        Ok(None)
    }

    fn save_membergroup(&self, _group: MembergroupData) -> Result<i64, ForumError> {
        Err(ForumError::Internal("membergroups not supported in SurrealService".into()))
    }

    fn list_group_members(&self, _group_id: i64) -> Result<Vec<GroupMember>, ForumError> {
        Ok(Vec::new())
    }

    fn remove_members_from_group(&self, _group_id: i64, _members: &[i64]) -> Result<(), ForumError> {
        Ok(())
    }

    fn get_membergroup_settings(&self) -> Result<MembergroupSettings, ForumError> {
        Ok(MembergroupSettings::default())
    }

    fn save_membergroup_settings(&self, _settings: MembergroupSettings) -> Result<(), ForumError> {
        Ok(())
    }

    fn delete_membergroups(&self, _group_ids: &[i64]) -> Result<(), ForumError> {
        Ok(())
    }

    fn remove_members_from_groups(
        &self,
        _member_ids: &[i64],
        _group_ids: Option<&[i64]>,
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn add_members_to_group(
        &self,
        _member_ids: &[i64],
        _group_id: i64,
        _assign_type: GroupAssignType,
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn list_membergroups_detailed(
        &self,
        _group_type: MembergroupListType,
    ) -> Result<Vec<MembergroupListEntry>, ForumError> {
        Ok(Vec::new())
    }

    fn groups_with_permissions(
        &self,
        _group_permissions: &[String],
        _board_permissions: &[String],
        _profile_id: i64,
    ) -> Result<std::collections::HashMap<String, PermissionSnapshot>, ForumError> {
        Ok(std::collections::HashMap::new())
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
        Ok(None)
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
        Ok(Vec::new())
    }

    fn delete_member(&self, _member_id: i64) -> Result<(), ForumError> {
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
    ) -> Result<std::collections::HashMap<i64, std::collections::HashMap<String, i32>>, ForumError> {
        Ok(std::collections::HashMap::new())
    }

    fn set_alert_prefs(&self, _member_id: i64, _prefs: &[(String, i32)]) -> Result<(), ForumError> {
        Ok(())
    }

    fn delete_alert_prefs(&self, _member_id: i64, _prefs: &[String]) -> Result<(), ForumError> {
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
        Some(0)
    }

    fn settings_last_updated(&self) -> i64 {
        0
    }

    fn list_ban_rules(&self) -> Result<Vec<BanRule>, ForumError> {
        Ok(Vec::new())
    }

    fn save_ban_rule(&self, _rule: BanRule) -> Result<i64, ForumError> {
        Err(ForumError::Internal("bans not supported".into()))
    }

    fn delete_ban_rule(&self, _rule_id: i64) -> Result<(), ForumError> {
        Ok(())
    }

    fn ban_logs(&self) -> Result<Vec<BanLogEntry>, ForumError> {
        Ok(Vec::new())
    }

    fn record_ban_hit(&self, _bans: &[i64], _email: Option<&str>) -> Result<(), ForumError> {
        Ok(())
    }

    fn find_member_by_name(&self, _name: &str) -> Result<Option<MemberRecord>, ForumError> {
        Ok(None)
    }

    fn find_members_by_name(&self, _names: &[String]) -> Result<Vec<MemberRecord>, ForumError> {
        Ok(Vec::new())
    }

    fn cleanup_pm_recipients(&self, _member_ids: &[i64]) -> Result<(), ForumError> {
        Ok(())
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

    fn save_pm_preferences(&self, _member_id: i64, _prefs: &PmPreferenceState) -> Result<(), ForumError> {
        Ok(())
    }

    fn record_pm_sent(&self, _sender_id: i64, _timestamp: chrono::DateTime<chrono::Utc>) -> Result<(), ForumError> {
        Ok(())
    }

    fn count_pm_sent_since(&self, _sender_id: i64, _since: chrono::DateTime<chrono::Utc>) -> Result<usize, ForumError> {
        Ok(0)
    }

    fn log_action(
        &self,
        _action: &str,
        _member_id: Option<i64>,
        _details: &Value,
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn list_action_logs(&self) -> Result<Vec<ActionLogEntry>, ForumError> {
        Ok(Vec::new())
    }

    fn clean_expired_bans(&self) -> Result<usize, ForumError> {
        Ok(0)
    }

    fn save_pm_draft(&self, _draft: PmDraftRecord) -> Result<i64, ForumError> {
        Err(ForumError::Internal("pm drafts not supported".into()))
    }

    fn delete_pm_draft(&self, _owner_id: i64, _draft_id: i64) -> Result<(), ForumError> {
        Ok(())
    }

    fn list_pm_drafts(
        &self,
        _owner_id: i64,
        _start: usize,
        _limit: usize,
    ) -> Result<Vec<PmDraftRecord>, ForumError> {
        Ok(Vec::new())
    }

    fn read_pm_draft(&self, _owner_id: i64, _draft_id: i64) -> Result<Option<PmDraftRecord>, ForumError> {
        Ok(None)
    }

    fn personal_message_overview(&self, _user_id: i64) -> Result<PersonalMessageOverview, ForumError> {
        Ok(PersonalMessageOverview::default())
    }

    fn personal_message_labels(&self, _user_id: i64) -> Result<Vec<PersonalMessageLabel>, ForumError> {
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
        Ok(PersonalMessagePage::default())
    }

    fn personal_message_popup(&self, _user_id: i64, _limit: usize) -> Result<Vec<PersonalMessageSummary>, ForumError> {
        Ok(Vec::new())
    }

    fn personal_message_detail(
        &self,
        _user_id: i64,
        _pm_id: i64,
    ) -> Result<Option<PersonalMessageDetail>, ForumError> {
        Ok(None)
    }

    fn send_personal_message(
        &self,
        _request: SendPersonalMessage,
    ) -> Result<PersonalMessageSendResult, ForumError> {
        Err(ForumError::Internal("pm send not supported".into()))
    }

    fn delete_personal_messages(
        &self,
        _user_id: i64,
        _folder: PersonalMessageFolder,
        _ids: &[i64],
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn mark_personal_messages(&self, _user_id: i64, _ids: &[i64], _read: bool) -> Result<(), ForumError> {
        Ok(())
    }

    fn prune_personal_messages(&self, _user_id: i64, _days: i64) -> Result<usize, ForumError> {
        Ok(0)
    }

    fn clear_personal_messages(
        &self,
        _user_id: i64,
        _folder: PersonalMessageFolder,
    ) -> Result<usize, ForumError> {
        Ok(0)
    }

    fn create_pm_label(&self, _user_id: i64, _name: &str) -> Result<i64, ForumError> {
        Err(ForumError::Internal("pm labels not supported".into()))
    }

    fn rename_pm_label(&self, _user_id: i64, _label_id: i64, _name: &str) -> Result<(), ForumError> {
        Ok(())
    }

    fn delete_pm_labels(&self, _user_id: i64, _labels: &[i64]) -> Result<(), ForumError> {
        Ok(())
    }

    fn label_personal_messages(
        &self,
        _user_id: i64,
        _ids: &[i64],
        _label_id: i64,
        _add: bool,
    ) -> Result<(), ForumError> {
        Ok(())
    }

    fn search_personal_messages(
        &self,
        _user_id: i64,
        _query: &PersonalMessageSearchQuery,
    ) -> Result<Vec<PersonalMessageSummary>, ForumError> {
        Ok(Vec::new())
    }
}
