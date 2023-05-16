use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub(super) struct Branding {
    pub(super) site_title: String,
    pub(super) use_logo: bool,
}

impl Default for Branding {
    fn default() -> Self {
        Self {
            site_title: "Rust Docs".to_string(),
            use_logo: false,
        }
    }
}
