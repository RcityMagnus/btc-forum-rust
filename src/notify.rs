use crate::services::{ForumContext, ForumService, NotifyPrefs, ServiceResult};
use serde_json::json;

pub fn get_notify_prefs<S: ForumService>(
    ctx: &mut ForumContext,
    service: &S,
) -> ServiceResult<NotifyPrefs> {
    let prefs = service.get_notify_prefs(ctx.user_info.id)?;
    ctx.context.set(
        "notify_prefs",
        json!({ "msg_auto_notify": prefs.msg_auto_notify }),
    );
    Ok(prefs)
}

pub fn set_auto_notify<S: ForumService>(
    ctx: &mut ForumContext,
    service: &S,
    enabled: bool,
) -> ServiceResult<NotifyPrefs> {
    let prefs = service.update_notify_pref(ctx.user_info.id, enabled)?;
    ctx.context.set("auto_notify", prefs.msg_auto_notify);
    Ok(prefs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::{ForumContext, InMemoryService};

    #[test]
    fn prefs_roundtrip() {
        let service = InMemoryService::default();
        let mut ctx = ForumContext::default();
        let prefs = set_auto_notify(&mut ctx, &service, true).unwrap();
        assert!(prefs.msg_auto_notify);
        let refreshed = get_notify_prefs(&mut ctx, &service).unwrap();
        assert!(refreshed.msg_auto_notify);
    }
}
