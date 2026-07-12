use serde::Serialize;

const REPO_OWNER: &str = "shabilullah";
const REPO_NAME: &str = "rustblocker";

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

/// Checks GitHub for a newer release. Returns `None` when already current.
pub fn check_for_update() -> Result<Option<UpdateInfo>, anyhow::Error> {
    use self_update::backends::github::ReleaseList;

    let releases = ReleaseList::configure()
        .repo_owner(REPO_OWNER)
        .repo_name(REPO_NAME)
        .build()?
        .fetch()?;

    let cur = current_version();

    // Find the newest non-prerelease release.
    let latest = match releases.iter().find(|r| {
        semver::Version::parse(r.version.trim_start_matches('v'))
            .map(|v| v.pre.is_empty())
            .unwrap_or(false)
    }) {
        Some(r) => r,
        None => return Ok(None),
    };

    // Compare versions.
    let latest_semver = semver::Version::parse(latest.version.trim_start_matches('v'))?;
    let cur_semver = semver::Version::parse(cur)?;

    if latest_semver <= cur_semver {
        return Ok(None);
    }
    let target = env!("TARGET_TRIPLE");

    let asset = latest
        .assets
        .iter()
        .find(|a| a.name.contains(target))
        .ok_or_else(|| anyhow::anyhow!("no matching asset found for target {}", target))?;

    Ok(Some(UpdateInfo {
        version: latest.version.clone(),
        notes: latest.body.clone().unwrap_or_default(),
        download_url: asset.download_url.clone(),
        current_version: cur.to_string(),
    }))
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
