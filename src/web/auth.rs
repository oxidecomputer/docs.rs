use anyhow::anyhow;
use axum::{
    extract::{FromRef, Query},
    http::Request,
    middleware::Next,
    response::{IntoResponse, Redirect, Response, Result},
    Extension,
};
use axum_extra::extract::cookie::{Cookie, Expiration, Key, SignedCookieJar};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use chrono::{DateTime, Utc};
use crates_index_diff::gix::bstr::ByteSlice;
use http::StatusCode;
use oauth2::{
    basic::{
        BasicErrorResponse, BasicRevocationErrorResponse, BasicTokenIntrospectionResponse,
        BasicTokenType,
    },
    reqwest::async_http_client,
    AuthUrl, AuthorizationCode, Client, ClientId, ClientSecret, CsrfToken, ExtraTokenFields,
    RedirectUrl, Scope, StandardRevocableToken, StandardTokenResponse, TokenUrl,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use time::OffsetDateTime;
use tracing::{info, trace};

use crate::{web::error::internal_error, Config};

use super::AppState;

// Duration (in seconds) that a user will remain logged in for
const SESSION_DURATION: i64 = 24 * 60 * 60;

// Duration (in seconds) that a user must complete a log in attempt before the csrf token expires
const CSRF_DURATION: i64 = 5 * 60;

// Cookie names

// Stores the session cookie that provides access to authentication protected routes
static AUTH_COOKIE: &str = "auth";

// Store the return path to send the user to after successful authentication
static AUTH_RETURN_COOKIE: &str = "after_auth";

// Stores the csrf token for verifying authentication returns
static AUTH_CSRF: &str = "auth_csrf";

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

pub type AuthClient = Client<
    BasicErrorResponse,
    AuthTokenResponse,
    BasicTokenType,
    BasicTokenIntrospectionResponse,
    StandardRevocableToken,
    BasicRevocationErrorResponse,
>;

// Generate an OAuth client from the app config for authenticating users
pub(super) fn auth_client(config: Arc<Config>) -> anyhow::Result<AuthClient> {
    Ok(AuthClient::new(
        ClientId::new(config.oauth_client_id.clone()),
        Some(ClientSecret::new(config.oauth_client_secret.clone())),
        AuthUrl::new(config.oauth_auth_url.clone())?,
        Some(TokenUrl::new(config.oauth_token_url.clone())?),
    )
    .set_redirect_uri(RedirectUrl::new(config.oauth_redirect_url.clone())?))
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

impl AuthFields {
    // Extract the id token returned from Google which provides identifying information on the
    // authenticated user
    fn token(&self) -> anyhow::Result<IdToken> {
        // Extract the id token returned from Google which provides identifying information on the
        // authenticated user
        let parts = self.id_token.split('.').collect::<Vec<_>>();

        let token_part = parts
            .get(1)
            .ok_or_else(|| anyhow!("OAuth response is missing an id token"))?;
        let decoded = URL_SAFE_NO_PAD.decode(token_part)?;
        let token = decoded.to_str()?;
        let id_token: IdToken = serde_json::from_str(token)?;

        Ok(id_token)
    }
}

#[derive(Debug, Deserialize, PartialEq, Serialize)]
pub struct IdToken {
    hd: String,
    email: String,
    email_verified: bool,
    sub: String,
}

impl IdToken {
    // Ensure that for the identified user:
    //   1. The email address belongs to the configured domain
    //   2. The email domain is set to the configured domain
    //   3. The IdP reports the email address as verified
    fn authorized(&self, valid_domain: &str) -> bool {
        self.email.ends_with(valid_domain) && self.hd == valid_domain && self.email_verified
    }
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
    jar: SignedCookieJar,
) -> Result<impl IntoResponse> {
    let (csrf_check, jar) = check_csrf(jar, &query.state);
    let (return_to, mut jar) = extract_return(jar);

    if !csrf_check {
        return Ok((jar, Redirect::to("/login-failure")).into_response());
    }

    // State has been validated, so try to exchange the authorization code for an access token
    let resp: AuthTokenResponse = client
        .exchange_code(AuthorizationCode::new(query.code.clone()))
        .request_async(async_http_client)
        .await
        .map_err(internal_error)?;

    let id_token = resp.extra_fields().token().map_err(internal_error)?;
    let authorized = id_token.authorized(&config.oauth_domain);

    if !authorized {
        return Ok(Redirect::to("/login-failure").into_response());
    }

    jar = jar.add(create_authorization_cookie(SESSION_DURATION).map_err(internal_error)?);

    info!(?id_token.sub, ?id_token.hd, ?id_token.email_verified, "Authorized oauth login");

    Ok((jar, Redirect::to(&return_to)).into_response())
}

pub(super) async fn authenticate(
    Extension(client): Extension<Arc<AuthClient>>,
    mut jar: SignedCookieJar,
) -> impl IntoResponse {
    let (url, csrf) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .url();

    // Store a crsf token for verifying the return response
    jar = jar.add(create_csrf_cookie(csrf.secret(), CSRF_DURATION));

    (jar, Redirect::to(url.as_ref()))
}

// Log the user out if they are logged in. This will attempt to delete all state cookies independent
// of the user being logged in.
pub(super) async fn logout(jar: SignedCookieJar) -> impl IntoResponse {
    (clear_state_cookies(jar), Redirect::to("/"))
}

// Check if the request is coming from an authorized user.
pub(super) async fn authorized<B>(req: Request<B>, next: Next<B>) -> Result<Response, StatusCode> {
    let config = req.extensions().get::<Arc<Config>>().unwrap();
    let mut jar = get_jar_from_request(&req);

    if !config.authentication_enabled || has_valid_cookie(&jar) {
        Ok(next.run(req).await)
    } else {
        // Delete any existing auth cookies
        jar = clear_state_cookies(jar);
        jar = jar.add(create_return_cookie(&req));

        Ok((jar, Redirect::to("/authenticate")).into_response())
    }
}

// Create a cookie for storing the return path that a user should be redirected to after login
fn create_return_cookie<B>(req: &Request<B>) -> Cookie<'static> {
    let mut return_to = Cookie::new(
        AUTH_RETURN_COOKIE,
        req.uri()
            .path_and_query()
            .map(|path| path.to_string())
            .unwrap_or("/".to_string()),
    );
    return_to.set_path("/");
    return_to
}

fn create_csrf_cookie(value: &str, duration: i64) -> Cookie<'static> {
    let mut cookie = Cookie::new(AUTH_CSRF, value.to_string());
    cookie.set_path("/");

    let expiration =
        Expiration::from(OffsetDateTime::now_utc()).map(|t| t + time::Duration::seconds(duration));
    cookie.set_expires(expiration);

    cookie
}

fn create_authorization_cookie(duration: i64) -> anyhow::Result<Cookie<'static>> {
    // Generate a stateless session cookie that grants access for a static duration. After which the
    // user will need to re-authenticate
    let valid_until = Utc::now() + chrono::Duration::seconds(duration);
    let value = AuthCookie { valid_until };
    let serialized = serde_json::to_string(&value)?;

    // Generate the actual session cookie and set its expiration to make the embedded value
    let cookie_expiration =
        Expiration::from(OffsetDateTime::now_utc()).map(|t| t + time::Duration::seconds(duration));
    let mut session_cookie = Cookie::new(AUTH_COOKIE, serialized);
    session_cookie.set_expires(cookie_expiration);

    Ok(session_cookie)
}

// Checks that a csrf token exists and has a matching value. Calling this function will consume the
// csrf cookie, removing it from the jar
fn check_csrf(mut jar: SignedCookieJar, value: &str) -> (bool, SignedCookieJar) {
    // Verify the return state and delete the token cookie
    let csrf_check = jar
        .get(AUTH_CSRF)
        .map(|cookie| {
            trace!(state = ?value, token = ?cookie.value(), "Test csrf token");
            cookie.value() == value
        })
        .unwrap_or(false);
    jar = jar.remove(Cookie::named(AUTH_CSRF));

    (csrf_check, jar)
}

// Extract a return path from the jar. Calling this function will consume the return path cookie,
// removing it from the jar
fn extract_return(mut jar: SignedCookieJar) -> (String, SignedCookieJar) {
    let return_cookie = jar.get(AUTH_RETURN_COOKIE);
    let return_to = return_cookie
        .map(|cookie| cookie.value().to_string())
        .unwrap_or("/".to_string());
    jar = jar.remove(Cookie::named(AUTH_RETURN_COOKIE));

    (return_to, jar)
}

// Delete any existing state cookies
fn clear_state_cookies(mut jar: SignedCookieJar) -> SignedCookieJar {
    jar = jar.remove(Cookie::named(AUTH_COOKIE));
    jar = jar.remove(Cookie::named("auth_crsf"));
    jar = jar.remove(Cookie::named(AUTH_RETURN_COOKIE));
    jar
}

fn get_jar_from_request<B>(req: &Request<B>) -> SignedCookieJar {
    let config = req.extensions().get::<Arc<Config>>().unwrap();
    let key = Key::from(config.session_key.as_bytes());
    SignedCookieJar::from_headers(req.headers(), key)
}

fn has_valid_cookie(jar: &SignedCookieJar) -> bool {
    jar.get(AUTH_COOKIE)
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
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum_extra::extract::{cookie::Key, SignedCookieJar};

    #[test]
    fn test_empty_jar_is_invalid() {
        let jar = SignedCookieJar::new(Key::generate());
        assert!(!has_valid_cookie(&jar))
    }

    #[test]
    fn test_jar_with_expired_cookie_is_invalid() {
        let mut jar = SignedCookieJar::new(Key::generate());
        let cookie = create_authorization_cookie(-1000).expect("Failed to create expired cookie");
        jar = jar.add(cookie);

        assert!(!has_valid_cookie(&jar))
    }

    #[test]
    fn test_jar_with_malformed_value_is_invalid() {
        let mut jar = SignedCookieJar::new(Key::generate());
        let mut cookie =
            create_authorization_cookie(1000).expect("Failed to create malformed cookie");
        cookie.set_value("random malformed value");
        jar = jar.add(cookie);

        assert!(!has_valid_cookie(&jar))
    }

    #[test]
    fn test_jar_with_valid_cookie() {
        let mut jar = SignedCookieJar::new(Key::generate());
        let cookie = create_authorization_cookie(1000).expect("Failed to create valid cookie");
        jar = jar.add(cookie);

        assert!(has_valid_cookie(&jar))
    }

    #[test]
    fn test_clears_cookies() {
        let mut jar = SignedCookieJar::new(Key::generate());
        jar = jar.add(Cookie::new(AUTH_COOKIE, AUTH_COOKIE));
        jar = jar.add(Cookie::new(AUTH_RETURN_COOKIE, AUTH_RETURN_COOKIE));
        jar = jar.add(Cookie::new(AUTH_CSRF, AUTH_CSRF));

        assert_eq!(3, jar.iter().count());

        jar = clear_state_cookies(jar);

        assert_eq!(1, jar.iter().count());
    }

    #[test]
    fn test_decodes_id_token() {
        let token = IdToken {
            hd: "test.com".to_string(),
            email: "foo@test.com".to_string(),
            email_verified: true,
            sub: "12345".to_string(),
        };
        let serialized = serde_json::to_string(&token).unwrap();
        let fields = AuthFields {
            id_token: format!("header.{}.signature", URL_SAFE_NO_PAD.encode(serialized)),
        };

        assert_eq!(token, fields.token().unwrap());
    }

    #[test]
    fn test_token_auth_checks() {
        let mut token = IdToken {
            hd: "fail.com".to_string(),
            email: "foo@pass.com".to_string(),
            email_verified: true,
            sub: "12345".to_string(),
        };

        // Check domain
        assert!(!token.authorized("pass.com"));

        token.hd = "pass.com".to_string();
        token.email = "foo@fail.com".to_string();

        // Check email
        assert!(!token.authorized("pass.com"));

        token.email = "foo@pass.com".to_string();
        token.email_verified = false;

        // Check verified
        assert!(!token.authorized("pass.com"));

        token.email_verified = true;

        // Check all
        assert!(token.authorized("pass.com"));
    }
}
