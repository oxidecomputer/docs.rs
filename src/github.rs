use anyhow::Result;
use chrono::Duration;
use github_app_authenticator::{
    permissions::{Permissions, ReadWrite},
    GitHubAppAuthenticator, GitHubInstallationAuthenticator, TokenRequest,
};
use http::header::USER_AGENT;
use serde::Deserialize;

static GITHUB_API_BASE: &str = "https://api.github.com";
static GITHUB_CLONE_BASE: &str = "https://github.com";

pub fn clone_url(owner: &str, repo: &str) -> String {
    format!("{}/{}/{}.git", GITHUB_CLONE_BASE, owner, repo)
}

#[derive(Debug, Deserialize)]
struct Installation {
    id: u32,
    account: Account,
}

#[derive(Debug, Deserialize)]
struct Account {
    login: String,
}

pub async fn get_installation_for_owner(
    authenticator: &GitHubAppAuthenticator,
    owner: &str,
) -> Result<Option<u32>> {
    let url = format!("{}/app/installations", GITHUB_API_BASE);
    let ua = authenticator.user_agent();
    let response = reqwest::Client::new()
        .get(url)
        .header(USER_AGENT, ua)
        .bearer_auth(authenticator.generate_jwt(Duration::seconds(30))?)
        .send()
        .await?;
    let installations: Vec<Installation> = response.json().await?;

    Ok(installations
        .into_iter()
        .find(|i| i.account.login == owner)
        .map(|i| i.id))
}

pub async fn get_build_token(
    authenticator: &GitHubInstallationAuthenticator,
    repository: String,
) -> Result<String> {
    let permissions = Permissions {
        contents: Some(ReadWrite::Read),
        pull_requests: Some(ReadWrite::Read),
        ..Default::default()
    };

    let token_request = TokenRequest {
        repositories: Some(vec![repository]),
        permissions: Some(permissions),
        ..Default::default()
    };

    let token = authenticator.access_token(&token_request).await?;

    Ok(token)
}
