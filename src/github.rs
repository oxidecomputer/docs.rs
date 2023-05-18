use anyhow::Result;
use github_app_authenticator::{
    permissions::{Permissions, ReadWrite},
    GitHubInstallationAuthenticator, TokenRequest,
};

pub async fn get_build_token(
    authenticator: &GitHubInstallationAuthenticator,
    repository: String,
) -> Result<String> {
    let mut token_request = TokenRequest::default();

    token_request.repositories = Some(vec![repository]);

    let mut permissions = Permissions::default();
    permissions.contents = Some(ReadWrite::Read);
    permissions.pull_requests = Some(ReadWrite::Read);
    token_request.permissions = Some(permissions);

    let token = authenticator.access_token(&token_request).await?;

    Ok(token)
}
