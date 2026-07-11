use anyhow::{Context, Result};
use rustls::ServerConfig;
use rustls_pemfile::{certs, private_key};
use std::io::BufReader;

use crate::db::{CertificateData, DbPool};

/// Load rustls ServerConfig from PEM-encoded certificate and private key.
pub fn load_rustls_config(private_key_pem: &[u8], cert_chain_pem: &[u8]) -> Result<ServerConfig> {
    // Parse certificate chain
    let mut cert_reader = BufReader::new(cert_chain_pem);
    let cert_chain = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .context("failed to parse certificate chain")?;

    if cert_chain.is_empty() {
        anyhow::bail!("no certificates found in chain");
    }

    // Parse private key
    let mut key_reader = BufReader::new(private_key_pem);
    let private_key = private_key(&mut key_reader)
        .context("failed to parse private key")?
        .ok_or_else(|| anyhow::anyhow!("no private key found"))?;

    // Build TLS config
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(cert_chain, private_key)
        .context("invalid certificate or key")?;

    Ok(config)
}

/// Load TLS configuration from database for the given domain.
/// Returns None if no certificate is stored.
pub async fn get_tls_config_from_db(pool: &DbPool, domain: &str) -> Result<Option<ServerConfig>> {
    // Get certificate from database
    let cert_data: Option<CertificateData> = tokio::task::spawn_blocking({
        let pool = pool.clone();
        let domain = domain.to_string();
        move || crate::db::get_certificate(&pool, &domain)
    })
    .await
    .context("database task failed")?
    .context("failed to query certificate")?;

    match cert_data {
        Some((private_key, certificate, expires_at)) => {
            // Check if certificate is expired or close to expiry
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .context("system time error")?
                .as_secs() as i64;

            if expires_at <= now {
                tracing::warn!(
                    "Certificate for {} has expired (expired at: {})",
                    domain,
                    expires_at
                );
                return Ok(None);
            }

            let days_remaining = (expires_at - now) / 86400;
            if days_remaining < 7 {
                tracing::warn!(
                    "Certificate for {} expires in {} days",
                    domain,
                    days_remaining
                );
            }

            // Load TLS config
            let config = load_rustls_config(&private_key, &certificate)
                .context("failed to load TLS config from database")?;

            tracing::info!(
                "Loaded certificate for {} (expires in {} days)",
                domain,
                days_remaining
            );

            Ok(Some(config))
        }
        None => {
            tracing::info!("No certificate found in database for: {}", domain);
            Ok(None)
        }
    }
}
