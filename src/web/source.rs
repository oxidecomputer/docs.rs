use super::{error::AxumResult, match_version_axum};
use crate::{
    db::Pool,
    impl_axum_webpage,
    utils::{get_correct_docsrs_style_file, spawn_blocking},
    web::{
        cache::CachePolicy, error::AxumNope, file::File as DbFile, headers::CanonicalUrl,
        MatchSemver, MetaData,
    },
    Storage,
};
use anyhow::Result;
use axum::{extract::Path, headers::HeaderMapExt, response::IntoResponse, Extension};

use postgres::Client;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{cmp::Ordering, sync::Arc};
use tracing::{debug, instrument};

/// A source file's name and mime type
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Serialize)]
struct File {
    /// The name of the file
    name: String,
    /// The mime type of the file
    mime: String,
}

impl File {
    fn from_path_and_mime(path: &str, mime: &str) -> File {
        let (name, mime) = if let Some((dir, _)) = path.split_once('/') {
            (dir, "dir")
        } else {
            (path, mime)
        };

        Self {
            name: name.to_owned(),
            mime: mime.to_owned(),
        }
    }
}

/// A list of source files
#[derive(Debug, Clone, PartialEq, Serialize)]
struct FileList {
    metadata: MetaData,
    files: Vec<File>,
}

impl FileList {
    /// Gets FileList from a request path
    ///
    /// All paths stored in database have this format:
    ///
    /// ```text
    /// [
    ///   ["text/plain", ".gitignore"],
    ///   ["text/x-c", "src/reseeding.rs"],
    ///   ["text/x-c", "src/lib.rs"],
    ///   ["text/x-c", "README.md"],
    ///   ...
    /// ]
    /// ```
    ///
    /// This function is only returning FileList for requested directory. If is empty,
    /// it will return list of files (and dirs) for root directory. req_path must be a
    /// directory or empty for root directory.
    #[instrument(skip(conn))]
    fn from_path(
        conn: &mut Client,
        name: &str,
        version: &str,
        version_or_latest: &str,
        folder: &str,
    ) -> Result<Option<FileList>> {
        let row = match conn.query_opt(
            "SELECT crates.name,
                        releases.version,
                        releases.description,
                        releases.target_name,
                        releases.rustdoc_status,
                        releases.files,
                        releases.default_target,
                        releases.doc_targets,
                        releases.yanked,
                        releases.doc_rustc_version
                FROM releases
                LEFT OUTER JOIN crates ON crates.id = releases.crate_id
                WHERE crates.name = $1 AND releases.version = $2",
            &[&name, &version],
        )? {
            Some(row) => row,
            None => return Ok(None),
        };

        let files = if let Some(files) = row.try_get::<_, Option<Value>>(5)? {
            files
        } else {
            return Ok(None);
        };

        let mut file_list = Vec::new();
        if let Some(files) = files.as_array() {
            file_list.reserve(files.len());

            for file in files {
                if let Some(file) = file.as_array() {
                    let mime = file[0].as_str().unwrap();
                    let path = file[1].as_str().unwrap();

                    // skip .cargo-ok generated by cargo
                    if path == ".cargo-ok" {
                        continue;
                    }

                    // look only files for req_path
                    if let Some(path) = path.strip_prefix(folder) {
                        let file = File::from_path_and_mime(path, mime);

                        // avoid adding duplicates, a directory may occur more than once
                        if !file_list.contains(&file) {
                            file_list.push(file);
                        }
                    }
                }
            }

            if file_list.is_empty() {
                return Ok(None);
            }

            file_list.sort_by(|a, b| {
                // directories must be listed first
                if a.mime == "dir" && b.mime != "dir" {
                    Ordering::Less
                } else if a.mime != "dir" && b.mime == "dir" {
                    Ordering::Greater
                } else {
                    a.name.to_lowercase().cmp(&b.name.to_lowercase())
                }
            });

            Ok(Some(FileList {
                metadata: MetaData {
                    name: row.get(0),
                    version: row.get(1),
                    version_or_latest: version_or_latest.to_string(),
                    description: row.get(2),
                    target_name: row.get(3),
                    rustdoc_status: row.get(4),
                    default_target: row.get(6),
                    doc_targets: MetaData::parse_doc_targets(row.get(7)),
                    yanked: row.get(8),
                    rustdoc_css_file: get_correct_docsrs_style_file(row.get(9))?,
                },
                files: file_list,
            }))
        } else {
            Ok(None)
        }
    }
}

#[derive(Debug, Clone, Serialize)]
struct SourcePage {
    file_list: FileList,
    show_parent_link: bool,
    file: Option<File>,
    file_content: Option<String>,
    canonical_url: CanonicalUrl,
    is_latest_url: bool,
}

impl_axum_webpage! {
    SourcePage = "crate/source.html",
    canonical_url = |page| Some(page.canonical_url.clone()),
    cache_policy = |page| if page.is_latest_url {
        CachePolicy::ForeverInCdn
    } else {
        CachePolicy::ForeverInCdnAndStaleInBrowser
    },
    cpu_intensive_rendering = true,
}

#[derive(Deserialize, Clone, Debug)]
pub(crate) struct SourceBrowserHandlerParams {
    name: String,
    version: String,
    #[serde(default)]
    path: String,
}

#[instrument(skip(pool, storage))]
pub(crate) async fn source_browser_handler(
    Path(SourceBrowserHandlerParams {
        mut name,
        version,
        path,
    }): Path<SourceBrowserHandlerParams>,
    Extension(storage): Extension<Arc<Storage>>,
    Extension(pool): Extension<Pool>,
) -> AxumResult<impl IntoResponse> {
    let v = match_version_axum(&pool, &name, Some(&version)).await?;

    debug!(?v, "Matched version for source file");

    if let Some(new_name) = &v.corrected_name {
        // `match_version` checked against -/_ typos, so if we have a name here we should
        // use that instead
        name = new_name.to_string();
    }

    debug!(?name, "Cleaned name");

    let (version, version_or_latest, is_latest_url) = match v.version {
        MatchSemver::Latest((version, _)) => (version, "latest".to_string(), true),
        MatchSemver::Exact((version, _)) => (version.clone(), version, false),
        MatchSemver::Semver((version, _)) => {
            return Ok(super::axum_cached_redirect(
                &format!("/crate/{name}/{version}/source/{path}"),
                CachePolicy::ForeverInCdn,
            )?
            .into_response());
        }
    };

    debug!(?version, version_or_latest, is_latest_url, "Extracted version data");

    let blob = spawn_blocking({
        let pool = pool.clone();
        let path = path.clone();
        let name = name.clone();
        let version = version.clone();
        move || {
            let mut conn = pool.get()?;
            let archive_storage: bool = conn
                .query_one(
                    "SELECT archive_storage
                     FROM releases
                     INNER JOIN crates ON releases.crate_id = crates.id
                     WHERE
                         name = $1 AND
                         version = $2",
                    &[&name, &version],
                )?
                .get::<_, bool>(0);

            // try to get actual file first
            // skip if request is a directory
            Ok(if !path.ends_with('/') {
                debug!(?name, ?version, ?path, "Read file from storage");
                storage
                    .fetch_source_file(&name, &version, &path, archive_storage)
                    .ok()
            } else {
                None
            })
        }
    })
    .await?;

    let canonical_url = CanonicalUrl::from_path(format!("/crate/{name}/latest/source/{path}"));

    let (file, file_content) = if let Some(blob) = blob {
        let is_text = blob.mime.starts_with("text") || blob.mime == "application/json";
        // serve the file with DatabaseFileHandler if file isn't text and not empty
        if !is_text && !blob.is_empty() {
            debug!("Read non-text blob");

            let mut response = DbFile(blob).into_response();
            response.headers_mut().typed_insert(canonical_url);
            response
                .extensions_mut()
                .insert(CachePolicy::ForeverInCdnAndStaleInBrowser);
            return Ok(response);
        } else if is_text && !blob.is_empty() {
            debug!("Read text blob");

            let path = blob
                .path
                .rsplit_once('/')
                .map(|(_, path)| path)
                .unwrap_or(&blob.path);
            (
                Some(File::from_path_and_mime(path, &blob.mime)),
                String::from_utf8(blob.content).ok(),
            )
        } else {
            debug!("Blob is empty");

            (None, None)
        }
    } else {
        debug!("No file blob found");

        (None, None)
    };

    debug!(?file, ?file_content, "Fetched file contents");

    let current_folder = if let Some(last_slash_pos) = path.rfind('/') {
        &path[..last_slash_pos + 1]
    } else {
        ""
    };

    let file_list = spawn_blocking({
        let name = name.clone();
        let current_folder = current_folder.to_string();
        move || {
            let mut conn = pool.get()?;
            FileList::from_path(
                &mut conn,
                &name,
                &version,
                &version_or_latest,
                &current_folder,
            )
        }
    })
    .await?
    .ok_or(AxumNope::ResourceNotFound)?;

    Ok(SourcePage {
        file_list,
        show_parent_link: !current_folder.is_empty(),
        file,
        file_content,
        canonical_url,
        is_latest_url,
    }
    .into_response())
}

#[cfg(test)]
mod tests {
    use crate::test::*;
    use crate::web::cache::CachePolicy;
    use kuchiki::traits::TendrilSink;
    use reqwest::StatusCode;
    use test_case::test_case;

    fn get_file_list_links(body: &str) -> Vec<String> {
        let dom = kuchiki::parse_html().one(body);

        dom.select(".package-menu > ul > li > a")
            .expect("invalid selector")
            .map(|el| {
                let attributes = el.attributes.borrow();
                attributes.get("href").unwrap().to_string()
            })
            .collect()
    }

    #[test_case(true)]
    #[test_case(false)]
    fn fetch_source_file_utf8_path(archive_storage: bool) {
        wrapper(|env| {
            let filename = "序.pdf";

            env.fake_release()
                .archive_storage(archive_storage)
                .name("fake")
                .version("0.1.0")
                .source_file(filename, b"some_random_content")
                .create()?;

            let web = env.frontend();
            let response = web
                .get(&format!("/crate/fake/0.1.0/source/{filename}"))
                .send()?;
            assert!(response.status().is_success());
            assert_eq!(
                response.headers().get("link").unwrap(),
                "<https://docs.rs/crate/fake/latest/source/%E5%BA%8F.pdf>; rel=\"canonical\"",
            );
            assert!(response.text()?.contains("some_random_content"));
            Ok(())
        });
    }

    #[test_case(true)]
    #[test_case(false)]
    fn fetch_source_file_content(archive_storage: bool) {
        wrapper(|env| {
            env.fake_release()
                .archive_storage(archive_storage)
                .name("fake")
                .version("0.1.0")
                .source_file("some_filename.rs", b"some_random_content")
                .create()?;
            let web = env.frontend();
            assert_success_cached(
                "/crate/fake/0.1.0/source/",
                web,
                CachePolicy::ForeverInCdnAndStaleInBrowser,
                &env.config(),
            )?;
            let response = web
                .get("/crate/fake/0.1.0/source/some_filename.rs")
                .send()?;
            assert!(response.status().is_success());
            assert_eq!(
                response.headers().get("link").unwrap(),
                "<https://docs.rs/crate/fake/latest/source/some_filename.rs>; rel=\"canonical\""
            );
            assert_cache_control(
                &response,
                CachePolicy::ForeverInCdnAndStaleInBrowser,
                &env.config(),
            );
            assert!(response.text()?.contains("some_random_content"));
            Ok(())
        });
    }

    #[test_case(true)]
    #[test_case(false)]
    fn fetch_binary(archive_storage: bool) {
        wrapper(|env| {
            env.fake_release()
                .archive_storage(archive_storage)
                .name("fake")
                .version("0.1.0")
                .source_file("some_file.pdf", b"some_random_content")
                .create()?;
            let web = env.frontend();
            let response = web.get("/crate/fake/0.1.0/source/some_file.pdf").send()?;
            assert!(response.status().is_success());
            assert_eq!(
                response.headers().get("link").unwrap(),
                "<https://docs.rs/crate/fake/latest/source/some_file.pdf>; rel=\"canonical\""
            );
            assert_eq!(
                response
                    .headers()
                    .get("content-type")
                    .unwrap()
                    .to_str()
                    .unwrap(),
                "application/pdf"
            );

            assert_cache_control(
                &response,
                CachePolicy::ForeverInCdnAndStaleInBrowser,
                &env.config(),
            );
            assert!(response.text()?.contains("some_random_content"));
            Ok(())
        });
    }

    #[test_case(true)]
    #[test_case(false)]
    fn cargo_ok_not_skipped(archive_storage: bool) {
        wrapper(|env| {
            env.fake_release()
                .archive_storage(archive_storage)
                .name("fake")
                .version("0.1.0")
                .source_file(".cargo-ok", b"ok")
                .source_file("README.md", b"hello")
                .create()?;
            let web = env.frontend();
            assert_success("/crate/fake/0.1.0/source/", web)?;
            Ok(())
        });
    }

    #[test_case(true)]
    #[test_case(false)]
    fn empty_file_list_dont_break_the_view(archive_storage: bool) {
        wrapper(|env| {
            let release_id = env
                .fake_release()
                .archive_storage(archive_storage)
                .name("fake")
                .version("0.1.0")
                .source_file("README.md", b"hello")
                .create()?;

            let path = "/crate/fake/0.1.0/source/README.md";
            let web = env.frontend();
            assert_success(path, web)?;

            env.db().conn().execute(
                "UPDATE releases
                     SET files = NULL
                     WHERE id = $1",
                &[&release_id],
            )?;

            assert_eq!(web.get(path).send()?.status(), StatusCode::NOT_FOUND);

            Ok(())
        });
    }

    #[test]
    fn latest_contains_links_to_latest() {
        wrapper(|env| {
            env.fake_release()
                .archive_storage(true)
                .name("fake")
                .version("0.1.0")
                .source_file(".cargo-ok", b"ok")
                .source_file("README.md", b"hello")
                .create()?;
            let resp = env.frontend().get("/crate/fake/latest/source/").send()?;
            assert_cache_control(&resp, CachePolicy::ForeverInCdn, &env.config());
            assert!(resp.url().as_str().ends_with("/crate/fake/latest/source/"));
            let body = String::from_utf8(resp.bytes().unwrap().to_vec()).unwrap();
            assert!(body.contains("<a href=\"/crate/fake/latest/builds\""));
            assert!(body.contains("<a href=\"/crate/fake/latest/source/\""));
            assert!(body.contains("<a href=\"/crate/fake/latest\""));
            assert!(body.contains("<a href=\"/crate/fake/latest/features\""));

            Ok(())
        });
    }

    #[test_case(true)]
    #[test_case(false)]
    fn directory_not_found(archive_storage: bool) {
        wrapper(|env| {
            env.fake_release()
                .archive_storage(archive_storage)
                .name("mbedtls")
                .version("0.2.0")
                .create()?;
            let web = env.frontend();
            assert_not_found("/crate/mbedtls/0.2.0/source/test/", web)?;
            Ok(())
        })
    }

    #[test_case(true)]
    #[test_case(false)]
    fn semver_handled(archive_storage: bool) {
        wrapper(|env| {
            env.fake_release()
                .archive_storage(archive_storage)
                .name("mbedtls")
                .version("0.2.0")
                .source_file("README.md", b"hello")
                .create()?;
            let web = env.frontend();
            assert_success("/crate/mbedtls/0.2.0/source/", web)?;
            assert_redirect_cached(
                "/crate/mbedtls/*/source/",
                "/crate/mbedtls/0.2.0/source/",
                CachePolicy::ForeverInCdn,
                web,
                &env.config(),
            )?;
            Ok(())
        })
    }

    #[test_case(true)]
    #[test_case(false)]
    fn literal_krate_description(archive_storage: bool) {
        wrapper(|env| {
            env.fake_release()
                .archive_storage(archive_storage)
                .name("rustc-ap-syntax")
                .version("178.0.0")
                .description("some stuff with krate")
                .source_file("fold.rs", b"fn foo() {}")
                .create()?;
            let web = env.frontend();
            assert_success_cached(
                "/crate/rustc-ap-syntax/178.0.0/source/fold.rs",
                web,
                CachePolicy::ForeverInCdnAndStaleInBrowser,
                &env.config(),
            )?;
            Ok(())
        })
    }

    #[test]
    fn cargo_special_filetypes_are_highlighted() {
        wrapper(|env| {
            env.fake_release()
                .name("fake")
                .version("0.1.0")
                .source_file("Cargo.toml.orig", b"[package]")
                .source_file("Cargo.lock", b"[dependencies]")
                .create()?;

            let web = env.frontend();

            let response = web
                .get("/crate/fake/0.1.0/source/Cargo.toml.orig")
                .send()?
                .text()?;
            assert!(response.contains(r#"<span class="syntax-source syntax-toml">"#));

            let response = web
                .get("/crate/fake/0.1.0/source/Cargo.lock")
                .send()?
                .text()?;
            assert!(response.contains(r#"<span class="syntax-source syntax-toml">"#));

            Ok(())
        });
    }

    #[test]
    fn dotfiles_with_extension_are_highlighted() {
        wrapper(|env| {
            env.fake_release()
                .name("fake")
                .version("0.1.0")
                .source_file(".rustfmt.toml", b"[rustfmt]")
                .create()?;

            let web = env.frontend();

            let response = web
                .get("/crate/fake/0.1.0/source/.rustfmt.toml")
                .send()?
                .text()?;
            assert!(response.contains(r#"<span class="syntax-source syntax-toml">"#));

            Ok(())
        });
    }

    #[test]
    fn json_is_served_as_rendered_html() {
        wrapper(|env| {
            env.fake_release()
                .name("fake")
                .version("0.1.0")
                .source_file("config.json", b"{}")
                .create()?;

            let web = env.frontend();

            let response = web.get("/crate/fake/0.1.0/source/config.json").send()?;
            assert!(response
                .headers()
                .get("content-type")
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html"));

            let text = response.text()?;
            assert!(text.starts_with(r#"<!DOCTYPE html>"#));

            // file list doesn't show "../"
            assert_eq!(get_file_list_links(&text), vec!["./config.json"]);

            Ok(())
        });
    }

    #[test]
    fn root_file_list() {
        wrapper(|env| {
            env.fake_release()
                .name("fake")
                .version("0.1.0")
                .source_file("folder1/some_filename.rs", b"some_random_content")
                .source_file("folder2/another_filename.rs", b"some_random_content")
                .source_file("root_filename.rs", b"some_random_content")
                .create()?;

            let web = env.frontend();
            let response = web.get("/crate/fake/0.1.0/source/").send()?;
            assert!(response.status().is_success());
            assert_cache_control(
                &response,
                CachePolicy::ForeverInCdnAndStaleInBrowser,
                &env.config(),
            );

            assert_eq!(
                get_file_list_links(&response.text()?),
                vec!["./folder1/", "./folder2/", "./root_filename.rs"]
            );
            Ok(())
        });
    }

    #[test]
    fn child_file_list() {
        wrapper(|env| {
            env.fake_release()
                .name("fake")
                .version("0.1.0")
                .source_file("folder1/some_filename.rs", b"some_random_content")
                .source_file("folder1/more_filenames.rs", b"some_random_content")
                .source_file("folder2/another_filename.rs", b"some_random_content")
                .source_file("root_filename.rs", b"some_random_content")
                .create()?;

            let web = env.frontend();
            let response = web
                .get("/crate/fake/0.1.0/source/folder1/some_filename.rs")
                .send()?;
            assert!(response.status().is_success());
            assert_cache_control(
                &response,
                CachePolicy::ForeverInCdnAndStaleInBrowser,
                &env.config(),
            );

            assert_eq!(
                get_file_list_links(&response.text()?),
                vec!["../", "./more_filenames.rs", "./some_filename.rs"],
            );
            Ok(())
        });
    }
}
