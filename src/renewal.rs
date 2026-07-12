use anyhow::{Context, Result};
use std::sync::Arc;
use std::time::Duration;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::acme::AcmeManager;
use crate::cloudflare::CloudflareClient;
use crate::db::{self, DbPool};

pub const AUTO_RENEWAL_INTERVAL_HOURS: u64 = 24;
pub const AUTO_RENEWAL_THRESHOLD_DAYS: i64 = 7;

/// Spawn a background task that checks for expiring certificates and renews them.
/// Runs periodically and renews certificates expiring within the configured threshold.
pub fn spawn_renewal_task(
    pool: DbPool,
    renewal_interval_hours: u64,
    renewal_threshold_days: i64,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(renewal_interval_hours * 3600));

        loop {
            interval.tick().await;

            info!("Running certificate renewal check");

            match check_and_renew_certificates(&pool, renewal_threshold_days).await {
                Ok(renewed) => {
                    if renewed > 0 {
                        info!("Successfully renewed {} certificate(s)", renewed);
                    } else {
                        info!("No certificates need renewal");
                    }
                }
                Err(e) => {
                    error!("Certificate renewal check failed: {}", e);
                }
            }
        }
    })
}

/// Check for expiring certificates and attempt to renew them.
/// Returns the number of certificates successfully renewed.
async fn check_and_renew_certificates(pool: &DbPool, threshold_days: i64) -> Result<usize> {
    // Get list of expiring certificates
    let expiring = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || db::list_expiring_certificates(&pool, threshold_days)
    })
    .await
    .context("task failed")?
    .context("failed to list expiring certificates")?;

    if expiring.is_empty() {
        return Ok(0);
    }

    info!(
        "Found {} certificate(s) expiring within {} days",
        expiring.len(),
        threshold_days
    );

    let mut renewed_count = 0;

    for domain in expiring {
        info!("Attempting to renew certificate for: {}", domain);

        match renew_certificate_for_domain(pool, &domain).await {
            Ok(_) => {
                info!("Successfully renewed certificate for: {}", domain);
                renewed_count += 1;
            }
            Err(e) => {
                error!("Failed to renew certificate for {}: {}", domain, e);
            }
        }
    }

    Ok(renewed_count)
}

/// Attempt to renew a certificate for a specific domain.
async fn renew_certificate_for_domain(pool: &DbPool, domain: &str) -> Result<()> {
    // Get required settings from database
    let (cloudflare_token, acme_email, directory_url, wildcard) = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || {
            let cloudflare_token = db::get_setting(&pool, "cloudflare_api_token")
                .context("Cloudflare API token not configured")?;
            let acme_email =
                db::get_setting(&pool, "acme_email").context("ACME email not configured")?;
            let directory_url = db::get_setting(&pool, "acme_directory_url")
                .unwrap_or_else(|| "https://acme-v02.api.letsencrypt.org/directory".to_string());
            let wildcard = db::get_setting(&pool, "wildcard_cert")
                .map(|v| v == "true")
                .unwrap_or(false);
            Ok::<_, anyhow::Error>((cloudflare_token, acme_email, directory_url, wildcard))
        }
    })
    .await
    .context("task failed")??;

    // Create Cloudflare client
    let cloudflare = Arc::new(CloudflareClient::new(cloudflare_token)?);

    // Create ACME manager
    let acme = AcmeManager::new(directory_url, acme_email, cloudflare);

    // Request new certificate
    info!("Ordering new certificate for: {}", domain);
    let (private_key, certificate) = acme.renew_certificate(domain, wildcard, None, "").await?;

    // Parse certificate to get expiry
    let expires_at = parse_certificate_expiry(&certificate)?;

    // Store in database
    tokio::task::spawn_blocking({
        let pool = pool.clone();
        let domain = domain.to_string();
        move || {
            db::store_certificate(&pool, &domain, &private_key, &certificate, expires_at)
                .map_err(|e| format!("Database error: {}", e))
        }
    })
    .await
    .context("task failed")?
    .map_err(|e| anyhow::anyhow!(e))?;

    info!("Stored renewed certificate for: {}", domain);
    Ok(())
}

/// Parse certificate expiry from PEM.
fn parse_certificate_expiry(cert_pem: &[u8]) -> Result<i64> {
    use x509_parser::prelude::*;

    let pem_parsed =
        ::pem::parse(cert_pem).map_err(|e| anyhow::anyhow!("Failed to parse PEM: {}", e))?;
    let cert = X509Certificate::from_der(pem_parsed.contents())?.1;

    // Convert ASN1Time to Unix timestamp
    let not_after = cert.validity().not_after.timestamp();

    Ok(not_after)
}

/// Check if any certificates are expiring soon on startup.
/// This is a one-time check that runs when the server starts.
pub async fn check_expiring_on_startup(pool: &DbPool, threshold_days: i64) -> Result<()> {
    info!("Checking for expiring certificates on startup");

    let expiring = tokio::task::spawn_blocking({
        let pool = pool.clone();
        move || db::list_expiring_certificates(&pool, threshold_days)
    })
    .await
    .context("task failed")?
    .context("failed to list expiring certificates")?;

    if expiring.is_empty() {
        info!("No certificates expiring within {} days", threshold_days);
        return Ok(());
    }

    warn!(
        "Warning: {} certificate(s) expiring within {} days: {}",
        expiring.len(),
        threshold_days,
        expiring.join(", ")
    );

    // Optionally trigger immediate renewal
    // Uncomment if you want auto-renewal on startup
    // match check_and_renew_certificates(pool, threshold_days).await {
    //     Ok(renewed) => {
    //         info!("Renewed {} certificate(s) on startup", renewed);
    //     }
    //     Err(e) => {
    //         error!("Failed to renew certificates on startup: {}", e);
    //     }
    // }

    Ok(())
}
