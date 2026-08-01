use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use serde::Serialize;

const REPO_OWNER: &str = "shabilullah";
const REPO_NAME: &str = "rustblocker";
const RELEASES_FEED: &str = "https://github.com/shabilullah/rustblocker/releases.atom";

/// Returns the compiled-in crate version.
pub fn current_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}

/// Returns the compiled-in build identifier.
pub fn build_id() -> &'static str {
    env!("RUSTBLOCKER_BUILD_ID")
}

#[derive(Serialize)]
pub struct UpdateInfo {
    pub version: String,
    pub notes: String,
    pub download_url: String,
    pub current_version: String,
}

/// Checks the GitHub releases feed for a newer stable release.
pub async fn check_for_update() -> Result<Option<UpdateInfo>> {
    let feed = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .user_agent(concat!("rustblocker/", env!("CARGO_PKG_VERSION")))
        .build()
        .context("build update HTTP client")?
        .get(RELEASES_FEED)
        .send()
        .await
        .context("fetch GitHub releases feed")?
        .error_for_status()
        .context("GitHub releases feed returned an error")?
        .text()
        .await
        .context("read GitHub releases feed")?;

    update_from_feed(&feed, current_version(), env!("TARGET_TRIPLE"))
}

fn update_from_feed(feed: &str, current: &str, target: &str) -> Result<Option<UpdateInfo>> {
    let current_semver = semver::Version::parse(current).context("parse current version")?;
    let latest = feed
        .split("<entry>")
        .skip(1)
        .filter_map(|entry| xml_text(entry, "title"))
        .filter_map(|tag| {
            semver::Version::parse(tag.trim_start_matches('v'))
                .ok()
                .filter(|version| version.pre.is_empty())
                .map(|version| (tag, version))
        })
        .max_by(|left, right| left.1.cmp(&right.1))
        .ok_or_else(|| anyhow!("GitHub releases feed contains no stable releases"))?;

    if latest.1 <= current_semver {
        return Ok(None);
    }

    let version = latest.0.to_string();
    Ok(Some(UpdateInfo {
        notes: String::new(),
        download_url: format!(
            "https://github.com/{REPO_OWNER}/{REPO_NAME}/releases/download/{version}/{REPO_NAME}-{version}-{target}.tar.gz"
        ),
        version,
        current_version: current.to_string(),
    }))
}

fn xml_text<'a>(input: &'a str, tag: &str) -> Option<&'a str> {
    let start_tag = format!("<{tag}>");
    let end_tag = format!("</{tag}>");
    let start = input.find(&start_tag)? + start_tag.len();
    let end = input[start..].find(&end_tag)? + start;
    Some(input[start..end].trim())
}

/// Downloads and replaces the current binary. Returns the new version string.
/// Caller MUST restart the process afterward.
pub fn apply_update() -> Result<String, anyhow::Error> {
    use self_update::backends::github::Update;

    let status = Update::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .bin_name("rustblocker")
        .current_version(current_version())
        .show_download_progress(false)
        .build()?
        .update()?;

    match status {
        self_update::Status::UpToDate(v) => Err(anyhow::anyhow!("already up to date ({v})")),
        self_update::Status::Updated(r) => Ok(r),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const FEED: &str = r#"
        <feed>
          <entry><title>v0.1.12</title></entry>
          <entry><title>v0.2.0-rc.1</title></entry>
          <entry><title>v0.1.11</title></entry>
        </feed>
    "#;

    #[test]
    fn release_feed_finds_newest_stable_target_asset() {
        let update = update_from_feed(FEED, "0.1.11", "x86_64-unknown-linux-musl")
            .expect("valid feed")
            .expect("new release");

        assert_eq!(update.version, "v0.1.12");
        assert_eq!(
            update.download_url,
            "https://github.com/shabilullah/rustblocker/releases/download/v0.1.12/rustblocker-v0.1.12-x86_64-unknown-linux-musl.tar.gz"
        );
    }

    #[test]
    fn release_feed_reports_current_version_as_up_to_date() {
        assert!(
            update_from_feed(FEED, "0.1.12", "x86_64-unknown-linux-musl")
                .expect("valid feed")
                .is_none()
        );
    }
}
