use serde::Serialize;
use std::env::var;

#[derive(Clone, Debug, Serialize)]
pub(super) struct SiteFeatures {
    pub(super) about: bool,
    pub(super) credit: bool,
    pub(super) feed: bool,
    pub(super) search: bool,
    pub(super) sitemap: bool,
    pub(super) webhook: bool,
}

impl Default for SiteFeatures {
    fn default() -> Self {
        Self {
            about: flag("FEATURE_ABOUT", false),
            credit: flag("FEATURE_CREDIT", true),
            feed: flag("FEATURE_FEED", false),
            search: flag("FEATURE_SEARCH", false),
            sitemap: flag("FEATURE_SITEMAP", false),
            webhook: flag("FEATURE_WEBHOOK", true),
        }
    }
}

fn flag(key: &str, default: bool) -> bool {
    var(key).and_then(|val| Ok(val.to_lowercase() == "true")).unwrap_or(default)
}