use anyhow::anyhow;
use axum::{
    extract::RawBody,
    headers::Header,
    response::{IntoResponse, Result},
    Extension, TypedHeader,
};
use hmac::{Hmac, Mac};
use http::{HeaderName, StatusCode};
use hyper::{body::to_bytes, Body};
use octorust::auth::Credentials;
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use tracing::{debug, error, info};

use crate::{
    github::get_build_token,
    utils::spawn_blocking,
    web::error::{bad_request, internal_error},
    BuildQueue, Config,
};

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Event {
    IssueComment(IssueCommentEvent),
    PullRequest(PullRequestEvent),
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum IssueCommentEvent {
    Created {
        action: CreateAction,
        comment: Comment,
        issue: Issue,
        repository: Repository,
        installation: Installation,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum PullRequestEvent {
    Synchronize {
        action: SynchronizeAction,
        pull_request: PullRequest,
        repository: Repository,
        installation: Installation,
    },
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Comment {
    id: u32,
    author_association: AuthorAssociation,
    body: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Issue {
    id: u32,
    number: u32,
    pull_request: Option<PullRequest>,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PullRequest {
    id: u32,
    number: u32,
    head: PullRequestHead,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct PullRequestHead {
    #[serde(rename = "ref")]
    ref_: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Repository {
    id: u32,
    clone_url: String,
    full_name: String,
    name: String,
    owner: Owner,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Owner {
    id: u32,
    login: String,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum AuthorAssociation {
    Collaborator,
    Contributor,
    None,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct Installation {
    id: u32,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CreateAction {
    Created,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EditAction {
    Edited,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum DeleteAction {
    Deleted,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum SynchronizeAction {
    Synchronize,
}

#[derive(Debug)]
struct CommentPayload {
    comment: Comment,
    issue: Issue,
    repository: Repository,
    installation: Installation,
}

#[derive(Debug)]
struct PullRequestPayload {
    pull_request: PullRequest,
    repository: Repository,
    installation: Installation,
}

impl CommentPayload {
    fn build_trigger(wh_build_trigger: &str) -> Regex {
        let param_trigger = format!("^{} (.*?)$", wh_build_trigger);
        Regex::new(&param_trigger).unwrap()
    }

    fn get_message(&self, config: &Config) -> Option<String> {
        debug!(?config.wh_build_trigger, "Testing request");

        let nl_re = Regex::new("(\\r\\n|\\n)").unwrap();
        let parts = nl_re.split(&self.comment.body);

        let pattern = Self::build_trigger(&config.wh_build_trigger);

        for part in parts {
            if let Some(message) = pattern.captures(part).and_then(|captures| captures.get(1)) {
                return Some(message.as_str().to_string());
            }
        }

        None
    }
}

pub(crate) async fn github_webhook_handler(
    Extension(config): Extension<Arc<Config>>,
    Extension(queue): Extension<Arc<BuildQueue>>,
    TypedHeader(signature): TypedHeader<GitHubSignatureHeader>,
    RawBody(body): RawBody<Body>,
) -> Result<impl IntoResponse> {
    // Check the request signature
    let body = to_bytes(body).await.map_err(bad_request)?;
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(config.wh_secret.as_bytes())
        .map_err(internal_error)?;
    mac.update(&body);
    let verified = mac.verify_slice(&signature.0).is_ok();

    if !verified {
        return Err(StatusCode::BAD_REQUEST.into());
    }

    let event: Event = serde_json::from_slice(&body).map_err(bad_request)?;

    info!("Handling incoming GitHub webhook");

    let processable = extract_request(event).ok_or_else(|| {
        debug!("Skipping unprocessable comment");
        StatusCode::OK
    })?;

    let build = processable
        .into_command(&config)
        .map_err(internal_error)?
        .ok_or_else(|| StatusCode::OK)?;

    info!(?build, "Processing build request");

    let authenticator = config
        .wh_app_authenticator
        .installation_authenticator(build.installation_id);
    let token = get_build_token(&authenticator, build.repo.clone())
        .await
        .map_err(internal_error)?;

    info!("Generated access token for fetch");

    let github =
        octorust::Client::new(&config.wh_user_agent, Credentials::Token(token.clone())).unwrap();
    let pr = github
        .pulls()
        .get(&build.owner, &build.repo, build.issue_number as i64)
        .await
        .map_err(internal_error)?;

    let branch = pr.body.head.ref_;

    info!(?branch, "Found branch name to build against");

    let tokened_url = build
        .clone_url
        .replace("https://", &format!("https://x-access-token:{}@", token));

    let task = spawn_blocking(move || {
        let res = match &build.name {
            Some(krate) => queue.add_github_crate(krate, &branch, 0, &tokened_url, false),
            None => queue.add_github_crate(&build.repo, &branch, 0, &tokened_url, true),
        };

        if res.is_ok() {
            info!(?build.name, ?branch, ?build.clone_url, "Scheduled build");
        }

        res
    })
    .await;

    match task {
        Ok(_) => Ok(StatusCode::ACCEPTED),
        Err(err) => {
            error!(?err, "Failed to queue build request");
            Err(internal_error(err))
        }
    }
}

fn extract_request(event: Event) -> Option<Box<dyn IntoBuildCommand + Send + Sync>> {
    match event {
        Event::IssueComment(issue_comment) => match issue_comment {
            IssueCommentEvent::Created {
                comment,
                issue,
                repository,
                installation,
                ..
            } => issue
                .pull_request
                .is_some()
                .then_some(Box::new(CommentPayload {
                    comment: comment,
                    issue: issue,
                    repository: repository,
                    installation: installation,
                })),
        },
        Event::PullRequest(pull_request) => match pull_request {
            PullRequestEvent::Synchronize {
                pull_request,
                repository,
                installation,
                ..
            } => Some(Box::new(PullRequestPayload {
                pull_request,
                repository,
                installation,
            })),
        },
    }
}

static GITHUB_SIGNATURE_HEADER_NAME: HeaderName = HeaderName::from_static("x-hub-signature-256");

#[derive(Debug)]
pub(crate) struct GitHubSignatureHeader(Vec<u8>);

impl Header for GitHubSignatureHeader {
    fn name() -> &'static http::HeaderName {
        &GITHUB_SIGNATURE_HEADER_NAME
    }

    fn decode<'i, I>(values: &mut I) -> std::result::Result<Self, axum::headers::Error>
    where
        Self: Sized,
        I: Iterator<Item = &'i http::HeaderValue>,
    {
        for value in values {
            let sig = value
                .to_str()
                .ok()
                .and_then(|value| hex::decode(value.trim_start_matches("sha256=")).ok());

            if let Some(sig) = sig {
                return Ok(Self(sig));
            }
        }

        Err(axum::headers::Error::invalid())
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, _values: &mut E) {
        unimplemented!()
    }
}

#[derive(Debug)]
pub struct BuildCommand {
    name: Option<String>,
    installation_id: u32,
    owner: String,
    repo: String,
    issue_number: u32,
    clone_url: String,
}

trait IntoBuildCommand {
    fn into_command(self: Box<Self>, config: &Config) -> anyhow::Result<Option<BuildCommand>>;
}

impl IntoBuildCommand for CommentPayload {
    fn into_command(self: Box<Self>, config: &Config) -> anyhow::Result<Option<BuildCommand>> {
        let message = self
            .get_message(&config)
            .ok_or_else(|| anyhow!("Comment did not contain a build trigger"))?;
        let pattern = Regex::new(r#"build ([^\s]+)"#)?;
        let captures = pattern
            .captures(&message)
            .ok_or_else(|| anyhow!("Comment did not contain a build message"))?;

        if captures.len() == 2 {
            let name = captures.get(1).unwrap();

            Ok(Some(BuildCommand {
                name: Some(name.as_str().to_string()),
                installation_id: self.installation.id,
                owner: self.repository.owner.login,
                repo: self.repository.name,
                issue_number: self.issue.number,
                clone_url: self.repository.clone_url,
            }))
        } else {
            Ok(None)
        }
    }
}

impl IntoBuildCommand for PullRequestPayload {
    fn into_command(self: Box<Self>, _config: &Config) -> anyhow::Result<Option<BuildCommand>> {
        Ok(Some(BuildCommand {
            name: None,
            installation_id: self.installation.id,
            owner: self.repository.owner.login,
            repo: self.repository.name,
            issue_number: self.pull_request.number,
            clone_url: self.repository.clone_url,
        }))
    }
}
