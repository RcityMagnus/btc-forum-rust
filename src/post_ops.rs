use crate::services::{
    ForumContext, ForumError, ForumService, PostSubmission, PostedMessage, ServiceResult,
};

#[derive(Clone, Debug)]
pub struct MessageOptions {
    pub id: Option<i64>,
    pub subject: String,
    pub body: String,
    pub icon: String,
    pub smileys_enabled: bool,
    pub attachments: Vec<i64>,
    pub approved: bool,
    pub poster_time: Option<i64>,
    pub send_notifications: bool,
}

impl Default for MessageOptions {
    fn default() -> Self {
        Self {
            id: None,
            subject: String::new(),
            body: String::new(),
            icon: "xx".into(),
            smileys_enabled: true,
            attachments: Vec::new(),
            approved: true,
            poster_time: None,
            send_notifications: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct TopicOptions {
    pub id: Option<i64>,
    pub board: i64,
    pub poll: Option<i64>,
    pub lock_mode: Option<i32>,
    pub sticky_mode: Option<i32>,
    pub mark_as_read: bool,
    pub is_approved: bool,
}

impl Default for TopicOptions {
    fn default() -> Self {
        Self {
            id: None,
            board: 0,
            poll: None,
            lock_mode: None,
            sticky_mode: None,
            mark_as_read: true,
            is_approved: true,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PosterOptions {
    pub id: i64,
    pub name: String,
    pub email: String,
    pub ip: String,
    pub update_post_count: bool,
}

impl Default for PosterOptions {
    fn default() -> Self {
        Self {
            id: 0,
            name: String::new(),
            email: String::new(),
            ip: String::new(),
            update_post_count: false,
        }
    }
}

pub fn create_post<S: ForumService>(
    service: &S,
    ctx: &ForumContext,
    msg: &mut MessageOptions,
    topic: &mut TopicOptions,
    _poster: &PosterOptions,
) -> ServiceResult<PostedMessage> {
    if msg.icon.is_empty() {
        msg.icon = "xx".into();
    }

    if topic.board == 0 {
        return Err(ForumError::Validation("missing_board".into()));
    }

    let submission = PostSubmission {
        topic_id: topic.id,
        board_id: topic.board,
        message_id: None,
        subject: msg.subject.clone(),
        body: msg.body.clone(),
        icon: msg.icon.clone(),
        approved: msg.approved,
        send_notifications: msg.send_notifications,
    };

    let posted = service.persist_post(ctx, submission)?;
    msg.id = Some(posted.message_id);
    topic.id = Some(posted.topic_id);

    Ok(posted)
}

pub fn modify_post<S: ForumService>(
    service: &S,
    ctx: &ForumContext,
    msg: &MessageOptions,
    topic: &TopicOptions,
    _poster: &PosterOptions,
) -> ServiceResult<PostedMessage> {
    let message_id = msg
        .id
        .ok_or_else(|| ForumError::Validation("no_message".into()))?;
    if topic.board == 0 {
        return Err(ForumError::Validation("missing_board".into()));
    }

    let submission = PostSubmission {
        topic_id: topic.id,
        board_id: topic.board,
        message_id: Some(message_id),
        subject: msg.subject.clone(),
        body: msg.body.clone(),
        icon: msg.icon.clone(),
        approved: msg.approved,
        send_notifications: msg.send_notifications,
    };

    service.persist_post(ctx, submission)
}
