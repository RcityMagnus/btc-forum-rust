mod admin;
mod attachments;
mod calendar;
mod controller;
mod display;
mod drafts;
mod editor;
mod errors;
mod logging;
mod manage_attachments;
mod manage_bans;
mod manage_membergroups;
mod manage_members;
mod manage_news;
mod manage_permissions;
mod manage_posts;
mod manage_server;
mod manage_settings;
mod memberlist;
mod moderation_center;
mod news;
mod notify;
mod personal_messages;
mod pm_context;
mod pm_ops;
mod poll;
mod post_ops;
mod profile_actions;
mod profile_export;
mod profile_modify;
mod profile_view;
mod register;
mod security;
mod services;
mod subs_auth;
mod subs_boards;
mod subs_membergroups;
mod subs_members;
mod subs_notify;
mod who;

use controller::post::PostController;
use personal_messages::{PersonalMessageController, ssi_welcome};
use services::{ForumContext, InMemoryService};

fn main() {
    let service = InMemoryService::default();
    let post_controller = PostController::new(service.clone());
    let pm_controller = PersonalMessageController::new(service.clone());

    let mut ctx = ForumContext::default();
    ctx.board_id = Some(1);
    ctx.topic_id = Some(1);
    ctx.user_info.is_guest = false;
    ctx.user_info.permissions.insert("post_new".into());
    ctx.post_vars.set("subject", "CLI example");
    ctx.post_vars
        .set("message", "Hello from Rust post controller");
    ctx.context.set("becomes_approved", true);

    if let Err(error) = post_controller.post(&mut ctx) {
        eprintln!("post() -> {error}");
    }
    if let Err(error) = post_controller.post2(&mut ctx) {
        eprintln!("post2() -> {error}");
    }
    if let Err(error) = post_controller.quote_fast(&mut ctx) {
        eprintln!("quote_fast() -> {error}");
    }
    if let Err(error) = post_controller.announce_topic(&mut ctx) {
        eprintln!("announce_topic() -> {error}");
    }

    let mut pm_ctx = ForumContext::default();
    pm_ctx.user_info.id = 2;
    pm_ctx.user_info.is_guest = false;
    pm_ctx
        .user_info
        .permissions
        .extend(["pm_read".into(), "pm_send".into()]);
    pm_ctx.scripturl = "https://forum.local".into();
    if let Err(error) = pm_controller.dispatch(&mut pm_ctx) {
        eprintln!("pm dispatch -> {error}");
    }
    if let Ok(message) = ssi_welcome(&service, &mut pm_ctx, true) {
        println!("{message}");
    }
}
