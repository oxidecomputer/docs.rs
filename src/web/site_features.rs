use serde::Serialize;

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
            about: false,
            credit: true,
            feed: false,
            search: false,
            sitemap: false,
            webhook: true,
        }
    }
}
