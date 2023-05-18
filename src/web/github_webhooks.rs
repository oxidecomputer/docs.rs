use axum::{
    headers::Header,
    response::{IntoResponse, Result},
    Extension, TypedHeader, extract::RawBody,
};
use hmac::{Hmac, Mac};
use http::{StatusCode, HeaderName};
use hyper::{Body, body::to_bytes};
use octorust::{auth::Credentials};
use regex::Regex;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::sync::Arc;
use tracing::{error, info, debug};

use crate::{web::error::{internal_error, bad_request}, BuildQueue, Config, utils::spawn_blocking, github::get_build_token};

#[derive(Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Event {
    IssueComment(IssueCommentEvent),
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
    url: String,
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

#[derive(Debug)]
struct ToProcess {
    comment: Comment,
    issue: Issue,
    repository: Repository,
    installation: Installation,
}

impl ToProcess {
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
                return Some(message.as_str().to_string())
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
    let mut mac = <Hmac::<Sha256> as Mac>::new_from_slice(config.wh_secret.as_bytes()).map_err(internal_error)?;
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

    let message = processable.get_message(&config).ok_or_else(|| {
        debug!("Comment does not contain a docs message");
        StatusCode::OK
    })?;

    info!(?message, "Extracted docs message");

    let build = BuildCommand::matches(&message, &config).ok_or_else(|| StatusCode::OK)?;

    info!(?build, "Processing build request");

    let authenticator = config.wh_app_authenticator.installation_authenticator(processable.installation.id);
    let token = get_build_token(&authenticator, processable.repository.name.clone()).await.map_err(internal_error)?;

    info!("Generated access token for fetch");

    let github = octorust::Client::new(&config.wh_user_agent, Credentials::Token(token.clone())).unwrap();
    let pr = github
        .pulls()
        .get(
            &processable.repository.owner.login,
            &processable.repository.name,
            processable.issue.number as i64,
        )
        .await
        .map_err(internal_error)?;

    let branch = pr.body.head.ref_;

    info!(?branch, "Found branch name to build against");

    let tokened_url = processable
        .repository
        .clone_url
        .replace("https://", &format!("https://x-access-token:{}@", token));

    let task = spawn_blocking(move || {
        let res = queue.add_github_crate(&build.name, &branch, 0, &tokened_url);

        if res.is_ok() {
            info!(?build.name, ?branch, ?processable.repository.clone_url, "Scheduled build");
        }

        res
    }).await;

    match task {
        Ok(_) => {
            Ok(StatusCode::ACCEPTED)
        },
        Err(err) => {
            error!(?err, "Failed to queue build request");
            Err(internal_error(err))
        }
    }
}

fn extract_request(event: Event) -> Option<ToProcess> {
    match event {
        Event::IssueComment(issue_comment) => match issue_comment {
            IssueCommentEvent::Created {
                comment,
                issue,
                repository,
                installation,
                ..
            } => {
                issue.pull_request.is_some().then_some(ToProcess {
                    comment: comment,
                    issue: issue,
                    repository: repository,
                    installation: installation,
                })
            },
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
            I: Iterator<Item = &'i http::HeaderValue> {
        for value in values {
            let sig = value.to_str().ok().and_then(|value| hex::decode(value.trim_start_matches("sha256=")).ok());

            if let Some(sig) = sig {
                return Ok(Self(sig))
            }
        }

        Err(axum::headers::Error::invalid())
    }

    fn encode<E: Extend<http::HeaderValue>>(&self, _values: &mut E) {
        unimplemented!()
    }
}

pub trait Command {
    fn matches(message: &str, config: &Config) -> Option<Self> where Self: Sized;
}

#[derive(Debug)]
pub struct BuildCommand {
    name: String
}

impl Command for BuildCommand {
    fn matches(message: &str, _config: &Config) -> Option<Self> {
        let pattern = Regex::new(r#"build ([^\s]+)"#).unwrap();

        let captures = pattern.captures(message)?;

        if captures.len() == 2 {
            let name = captures.get(1)?;

            Some(BuildCommand {
                name: name.as_str().to_string(),
            })
        } else {
            None
        }
    }
}