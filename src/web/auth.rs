use anyhow::anyhow;
use axum::{response::{IntoResponse, Redirect, Result, Response}, Extension, extract::{Query, FromRef}, http::{Request}, middleware::Next};
use axum_extra::extract::cookie::{SignedCookieJar, Cookie, Key, Expiration};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{Utc, DateTime};
use crates_index_diff::gix::bstr::ByteSlice;
use http::StatusCode;
use oauth2::{basic::{BasicTokenType, BasicErrorResponse, BasicTokenIntrospectionResponse, BasicRevocationErrorResponse}, CsrfToken, Scope, AuthorizationCode, reqwest::async_http_client, TokenUrl, ClientSecret, ClientId, AuthUrl, RedirectUrl, StandardTokenResponse, Client, StandardRevocableToken, ExtraTokenFields};
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use std::sync::Arc;
use tracing::{info, trace};

use crate::{Config, web::error::internal_error};

use super::AppState;

// Two week cookie durations
const SESSION_DURATION: i64 = 60;

// Client authorization cookie. Internally stores an expiration date that is checked per request
#[derive(Deserialize, Serialize)]
pub(super) struct AuthCookie {
    valid_until: DateTime<Utc>,
}

impl FromRef<AppState> for Key {
    fn from_ref(state: &AppState) -> Self {
        state.session_key.clone()
    }
}

type AuthTokenResponse = StandardTokenResponse<AuthFields, BasicTokenType>;

type AuthClient = Client<
    BasicErrorResponse,
    AuthTokenResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse
>;

// Generate an OAuth client from the app config for authenticating users
pub(super) fn auth_client(config: Arc<Config>) -> anyhow::Result<AuthClient> {
    Ok(AuthClient::new(
        ClientId::new(config.oauth_client_id.clone()),
        Some(ClientSecret::new(config.oauth_client_secret.clone())),
        AuthUrl::new(config.oauth_auth_url.clone())?,
        Some(TokenUrl::new(config.oauth_token_url.clone())?),
    ).set_redirect_uri(RedirectUrl::new(config.oauth_redirect_url.clone())?))
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub(super) struct AuthParams {
    code: String,
    state: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct AuthFields {
    id_token: String,
}

#[derive(Debug, Deserialize, Serialize)]
pub struct IdToken {
    hd: String,
    email: String,
    email_verified: bool,
    sub: String,
}

impl ExtraTokenFields for AuthFields {}

// Accept a callback request coming from Google to finish authentication and generate an
// authorization cookie for the client. This endpoint will always clear the temporary cookies
// (return path and csrf) that are generated as a result of the login process. If the authentication
// details are accepted, the user will be redirected to the stored return path with an
// authorization cookie. Otherwise they will be redirected back to the index
pub(super) async fn authorize(
    Query(query): Query<AuthParams>,
    Extension(config): Extension<Arc<Config>>,
    Extension(client): Extension<Arc<AuthClient>>,
    mut jar: SignedCookieJar,
) -> Result<impl IntoResponse> {

    // Verify the return state and delete the token cookie
    let csrf_check = jar.get("auth_csrf").map(|cookie| {
        trace!(state = ?query.state, token = ?cookie.value(), "Test csrf token");
        cookie.value() == query.state
    }).unwrap_or(false);
    jar = jar.remove(Cookie::named("auth_csrf"));

    // Attempt to extract the redirect path from a separate cookie, or redirect to the index
    // otherwise. This is done early so that it can be deleted
    let return_cookie = jar.get("after_auth");
    let return_to = return_cookie.as_ref().map(|cookie| cookie.value()).unwrap_or("/");
    jar = jar.remove(Cookie::named("after_auth"));

    if !csrf_check {
        return Ok((jar, Redirect::to("/")).into_response())
    }

    // State has been validated, so try to exchange the authorization code for an access token
    let resp: AuthTokenResponse = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .map_err(internal_error)?;

    // Extract the id token returned from Google which provides identifying information on the
    // authenticated user
    let parts = resp.extra_fields().id_token.split('.').collect::<Vec<_>>();

    let token_part = parts.get(1).ok_or_else(|| anyhow!("OAuth response is missing an id token")).map_err(internal_error)?;
    let decoded = URL_SAFE_NO_PAD.decode(token_part).map_err(internal_error)?;
    let token = decoded.to_str().map_err(internal_error)?;
    let id_token: IdToken = serde_json::from_str(token).map_err(internal_error)?;

    // Ensure that for the authenticated user:
    //   1. The email address belongs to the configured domain
    //   2. The email domain is set to the configured domain
    //   3. The IdP reports the email address as verified
    let authorized = id_token.email.ends_with(&config.oauth_domain)
        && id_token.hd == config.oauth_domain
        && id_token.email_verified;

    if !authorized {
        return Ok(Redirect::to("/").into_response())
    }

    // Generate a stateless session cookie that grants access for a static duration. After which the
    // user will need to re-authenticate
    let valid_until = Utc::now() + chrono::Duration::seconds(SESSION_DURATION);
    let value = AuthCookie { valid_until };
    let serialized = serde_json::to_string(&value).map_err(internal_error)?;

    // Generate the actual session cookie and set its expiration to make the embedded value
    let cookie_expiration = Expiration::from(OffsetDateTime::now_utc()).map(|t| t + time::Duration::seconds(SESSION_DURATION));
    let mut session_cookie = Cookie::new(config.session_cookie.clone(), serialized);
    session_cookie.set_expires(cookie_expiration);
    jar = jar.add(session_cookie);

    info!(?id_token.sub, "Authorized oauth login");

    Ok((jar, Redirect::to(return_to)).into_response())
}

pub(super) async fn login(
    Extension(client): Extension<Arc<AuthClient>>,
    mut jar: SignedCookieJar,
) -> impl IntoResponse {
    let (url, csrf) = client.authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .url();

    // Store a crsf token for verifying the return response
    jar = jar.add(Cookie::new("auth_csrf", csrf.secret().clone()));

    (jar, Redirect::to(&url.to_string()))
}


// Log the user out if they are logged in. This will attempt to delete all state cookies independent
// of the user being logged in.
pub(super) async fn logout(
    Extension(config): Extension<Arc<Config>>,
    mut jar: SignedCookieJar,
) -> impl IntoResponse {

    // Delete any existing state cookies
    jar = jar.remove(Cookie::named(config.session_cookie.clone()));
    jar = jar.remove(Cookie::named("auth_crsf"));
    jar = jar.remove(Cookie::named("after_auth"));

    (jar, Redirect::to("/"))
}

// Check if the request is coming from an authorized user.
pub(super) async fn authenticated<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let extensions = req.extensions();
    let config = extensions.get::<Arc<Config>>().unwrap();
    
    let key = Key::from(config.session_key.as_bytes());
    let mut jar = SignedCookieJar::from_headers(req.headers(), key);

    let is_authenticated = jar
        .get(&config.session_cookie)
        .and_then(|verified_cookie| {
            match serde_json::from_str::<AuthCookie>(verified_cookie.value()) {
                Ok(value) => Some(value),
                Err(err) => {
                    info!(?err, "Failed to deserialize session cookie");
                    None
                }
            }
        })
        .map(|value| {
            let is_valid = value.valid_until >= Utc::now();

            if !is_valid {
                info!("Found expired session cookie");
            }

            is_valid
        })
        .unwrap_or(false);

    if is_authenticated {
        Ok(next.run(req).await)
    } else {
        // Delete any existing auth cookies
        jar = jar.remove(Cookie::named(config.session_key.clone()));

        let mut return_to = Cookie::new("after_auth", req.uri().path_and_query().map(|path| path.to_string()).unwrap_or("/".to_string()));
        return_to.set_path("/");
        jar = jar.add(return_to);

        Ok((jar, Redirect::to("/login")).into_response())
    }
}