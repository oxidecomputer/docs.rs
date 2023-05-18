use std::borrow::Cow;
use tracing::{error, warn};

use crate::{
    storage::PathNotFoundError,
    web::{releases::Search, AxumErrorPage},
};
use axum::{
    http::StatusCode,
    response::{ErrorResponse, IntoResponse, Response as AxumResponse},
};

#[derive(Debug, thiserror::Error)]
#[allow(dead_code)] // FIXME: remove after iron is gone
pub enum AxumNope {
    #[error("Requested resource not found")]
    ResourceNotFound,
    #[error("Requested build not found")]
    BuildNotFound,
    #[error("Requested crate not found")]
    CrateNotFound,
    #[error("Requested owner not found")]
    OwnerNotFound,
    #[error("Requested crate does not have specified version")]
    VersionNotFound,
    #[error("Search yielded no results")]
    NoResults,
    #[error("Internal server error")]
    InternalServerError,
    #[error("internal error")]
    InternalError(anyhow::Error),
    #[error("bad request")]
    BadRequest,
}

impl IntoResponse for AxumNope {
    fn into_response(self) -> AxumResponse {
        match self {
            AxumNope::ResourceNotFound => {
                // user tried to navigate to a resource (doc page/file) that doesn't exist
                AxumErrorPage {
                    title: "The requested resource does not exist",
                    message: "no such resource".into(),
                    status: StatusCode::NOT_FOUND,
                }
                .into_response()
            }

            AxumNope::BuildNotFound => AxumErrorPage {
                title: "The requested build does not exist",
                message: "no such build".into(),
                status: StatusCode::NOT_FOUND,
            }
            .into_response(),

            AxumNope::CrateNotFound => {
                // user tried to navigate to a crate that doesn't exist
                // TODO: Display the attempted crate and a link to a search for said crate
                AxumErrorPage {
                    title: "The requested crate does not exist",
                    message: "no such crate".into(),
                    status: StatusCode::NOT_FOUND,
                }
                .into_response()
            }

            AxumNope::OwnerNotFound => AxumErrorPage {
                title: "The requested owner does not exist",
                message: "no such owner".into(),
                status: StatusCode::NOT_FOUND,
            }
            .into_response(),

            AxumNope::VersionNotFound => {
                // user tried to navigate to a crate with a version that does not exist
                // TODO: Display the attempted crate and version
                AxumErrorPage {
                    title: "The requested version does not exist",
                    message: "no such version for this crate".into(),
                    status: StatusCode::NOT_FOUND,
                }
                .into_response()
            }
            AxumNope::NoResults => {
                // user did a search with no search terms
                Search {
                    title: "No results given for empty search query".to_owned(),
                    status: StatusCode::NOT_FOUND,
                    ..Default::default()
                }
                .into_response()
            }
            AxumNope::BadRequest => AxumErrorPage {
                title: "Bad request",
                message: "Bad request".into(),
                status: StatusCode::BAD_REQUEST,
            }
            .into_response(),
            AxumNope::InternalServerError => {
                // something went wrong, details should have been logged
                AxumErrorPage {
                    title: "Internal server error",
                    message: "internal server error".into(),
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                }
                .into_response()
            }
            AxumNope::InternalError(source) => {
                let web_error = crate::web::AxumErrorPage {
                    title: "Internal Server Error",
                    message: Cow::Owned(source.to_string()),
                    status: StatusCode::INTERNAL_SERVER_ERROR,
                };

                crate::utils::report_error(&source);

                web_error.into_response()
            }
        }
    }
}

impl From<anyhow::Error> for AxumNope {
    fn from(err: anyhow::Error) -> Self {
        match err.downcast::<AxumNope>() {
            Ok(axum_nope) => axum_nope,
            Err(err) => match err.downcast::<PathNotFoundError>() {
                Ok(_) => AxumNope::ResourceNotFound,
                Err(err) => AxumNope::InternalError(err),
            },
        }
    }
}

pub(crate) type AxumResult<T> = Result<T, AxumNope>;

pub fn bad_request(err: impl Into<anyhow::Error>) -> ErrorResponse {
    let err: anyhow::Error = err.into();
    warn!(?err, "Internal server error");
    ErrorResponse::from((StatusCode::BAD_REQUEST, format!("{}", err)))
}

pub fn internal_error(err: impl Into<anyhow::Error>) -> ErrorResponse {
    let err: anyhow::Error = err.into();
    error!(?err, "Internal server error");
    ErrorResponse::from((StatusCode::INTERNAL_SERVER_ERROR, format!("{}", err)))
}

#[cfg(test)]
mod tests {
    use crate::test::wrapper;
    use kuchiki::traits::TendrilSink;

    #[test]
    fn check_404_page_content_crate() {
        wrapper(|env| {
            let page = kuchiki::parse_html().one(
                env.frontend()
                    .get("/crate-which-doesnt-exist")
                    .send()?
                    .text()?,
            );
            assert_eq!(page.select("#crate-title").unwrap().count(), 1);
            assert_eq!(
                page.select("#crate-title")
                    .unwrap()
                    .next()
                    .unwrap()
                    .text_contents(),
                "The requested crate does not exist",
            );

            Ok(())
        });
    }

    #[test]
    fn check_404_page_content_resource() {
        wrapper(|env| {
            let page = kuchiki::parse_html().one(
                env.frontend()
                    .get("/resource-which-doesnt-exist.js")
                    .send()?
                    .text()?,
            );
            assert_eq!(page.select("#crate-title").unwrap().count(), 1);
            assert_eq!(
                page.select("#crate-title")
                    .unwrap()
                    .next()
                    .unwrap()
                    .text_contents(),
                "The requested resource does not exist",
            );

            Ok(())
        });
    }

    #[test]
    fn check_404_page_content_not_semver_version() {
        wrapper(|env| {
            env.fake_release().name("dummy").create()?;
            let page =
                kuchiki::parse_html().one(env.frontend().get("/dummy/not-semver").send()?.text()?);
            assert_eq!(page.select("#crate-title").unwrap().count(), 1);
            assert_eq!(
                page.select("#crate-title")
                    .unwrap()
                    .next()
                    .unwrap()
                    .text_contents(),
                "The requested version does not exist",
            );

            Ok(())
        });
    }

    #[test]
    fn check_404_page_content_nonexistent_version() {
        wrapper(|env| {
            env.fake_release().name("dummy").version("1.0.0").create()?;
            let page = kuchiki::parse_html().one(env.frontend().get("/dummy/2.0").send()?.text()?);
            assert_eq!(page.select("#crate-title").unwrap().count(), 1);
            assert_eq!(
                page.select("#crate-title")
                    .unwrap()
                    .next()
                    .unwrap()
                    .text_contents(),
                "The requested version does not exist",
            );

            Ok(())
        });
    }

    #[test]
    fn check_404_page_content_any_version_all_yanked() {
        wrapper(|env| {
            env.fake_release()
                .name("dummy")
                .version("1.0.0")
                .yanked(true)
                .create()?;
            let page = kuchiki::parse_html().one(env.frontend().get("/dummy/*").send()?.text()?);
            assert_eq!(page.select("#crate-title").unwrap().count(), 1);
            assert_eq!(
                page.select("#crate-title")
                    .unwrap()
                    .next()
                    .unwrap()
                    .text_contents(),
                "The requested version does not exist",
            );

            Ok(())
        });
    }
}
