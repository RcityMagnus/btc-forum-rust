use crate::personal_messages::pm_link;
use crate::security::is_not_banned;
use crate::services::{ForumContext, ForumError, ForumService, MessageData, ServiceResult};
use serde_json::json;

pub struct DisplayController<S: ForumService> {
    service: S,
}

impl<S: ForumService> DisplayController<S> {
    pub fn new(service: S) -> Self {
        Self { service }
    }

    pub fn display(&self, ctx: &mut ForumContext) -> ServiceResult<()> {
        is_not_banned(&self.service, ctx, false)?;
        let topic_id = ctx
            .topic_id
            .ok_or_else(|| ForumError::Validation("no_topic".into()))?;

        self.service.load_template(ctx, "Display")?;
        self.service.increment_topic_views(topic_id)?;

        let per_page = ctx.mod_settings.int("defaultMaxMessages").unwrap_or(20);
        let start = ctx.request.int("start").unwrap_or(0);

        let messages = self
            .service
            .fetch_topic_messages(topic_id, start, per_page)?;

        let rendered: Vec<_> = messages
            .iter()
            .map(|msg| render_message(ctx, msg))
            .collect();
        ctx.context.set("messages", rendered);
        ctx.context.set("page_start", start);
        ctx.context.set("messages_per_page", per_page);

        Ok(())
    }
}

fn render_message(ctx: &ForumContext, msg: &MessageData) -> serde_json::Value {
    let pm_url = pm_link(ctx, msg.member_id);
    json!({
        "id": msg.id,
        "subject": msg.subject,
        "body": msg.body,
        "author": msg.member_id,
        "send_pm": pm_url,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn display_loads_messages() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        ctx.topic_id = Some(1);
        ctx.mod_settings.set("defaultMaxMessages", 10);
        DisplayController::new(service)
            .display(&mut ctx)
            .expect("display should load messages");
    }
}
