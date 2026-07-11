use anyhow::{Context, Result};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt, NewAccount, NewOrder,
    OrderStatus,
};
use std::sync::Arc;
use tracing::{info, warn};

use crate::cloudflare::CloudflareClient;

/// ACME manager for certificate acquisition and renewal.
pub struct AcmeManager {
    directory_url: String,
    email: String,
    cloudflare: Arc<CloudflareClient>,
}

impl AcmeManager {
    /// Create a new ACME manager.
    pub fn new(directory_url: String, email: String, cloudflare: Arc<CloudflareClient>) -> Self {
        Self {
            directory_url,
            email,
            cloudflare,
        }
    }

    /// Order and obtain a certificate for the given domain.
    /// Returns (private_key_pem, cert_chain_pem).
    pub async fn order_certificate(
        &self,
        domain: &str,
        wildcard: bool,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        info!("Starting ACME certificate order for: {}", domain);

        // Determine directory URL
        let url = if self.directory_url.contains("staging") {
            LetsEncrypt::Staging.url()
        } else {
            LetsEncrypt::Production.url()
        };

        // Create account
        let (account, _credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", self.email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            url,
            None,
        )
        .await
        .context("failed to create ACME account")?;

        info!("ACME account created");

        // Prepare identifiers
        let identifiers = if wildcard {
            vec![
                Identifier::Dns(format!("*.{}", domain)),
                Identifier::Dns(domain.to_string()),
            ]
        } else {
            vec![Identifier::Dns(domain.to_string())]
        };

        // Create order
        let mut order = account
            .new_order(&NewOrder {
                identifiers: &identifiers,
            })
            .await
            .context("failed to create ACME order")?;

        let state = order.state();
        info!("Order state: {:?}", state.status);

        if !matches!(state.status, OrderStatus::Pending) {
            anyhow::bail!("unexpected initial order status: {:?}", state.status);
        }

        // Get authorizations
        let authorizations = order.authorizations().await?;

        // Process each authorization
        for authz in &authorizations {
            if authz.status == AuthorizationStatus::Valid {
                info!("Authorization already valid for: {:?}", authz.identifier);
                continue;
            }

            if authz.status != AuthorizationStatus::Pending {
                anyhow::bail!(
                    "unexpected authorization status for {:?}: {:?}",
                    authz.identifier,
                    authz.status
                );
            }

            // Get DNS-01 challenge
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Dns01)
                .context("no DNS-01 challenge found")?;

            let Identifier::Dns(domain_name) = &authz.identifier;
            info!("Processing DNS-01 challenge for: {}", domain_name);

            // Get challenge key authorization and DNS value
            let key_auth = order.key_authorization(challenge);
            let dns_value = key_auth.dns_value();

            // Create TXT record name
            let record_name = format!("_acme-challenge.{}", domain_name);

            // Find zone and create record
            let zone_id = self.cloudflare.find_zone_id(domain_name).await?;
            info!("Creating TXT record: {} = {}", record_name, dns_value);

            let record_id = self
                .cloudflare
                .create_txt_record(&zone_id, &record_name, &dns_value)
                .await?;

            // Wait for DNS propagation
            info!("Waiting 10 seconds for DNS propagation");
            tokio::time::sleep(tokio::time::Duration::from_secs(10)).await;

            // Notify ACME to validate
            order
                .set_challenge_ready(&challenge.url)
                .await
                .context("failed to set challenge ready")?;

            info!("Challenge set ready, waiting for validation");

            // Clean up DNS record after delay
            let cloudflare_clone = self.cloudflare.clone();
            let zone_id_clone = zone_id.clone();
            let record_id_clone = record_id.clone();
            let record_name_clone = record_name.clone();
            tokio::spawn(async move {
                tokio::time::sleep(tokio::time::Duration::from_secs(60)).await;
                if let Err(e) = cloudflare_clone
                    .delete_txt_record(&zone_id_clone, &record_id_clone)
                    .await
                {
                    warn!("Failed to clean up TXT record {}: {}", record_name_clone, e);
                } else {
                    info!("Cleaned up TXT record: {}", record_name_clone);
                }
            });
        }

        // Poll until order is ready
        info!("Polling for order to become ready");
        let mut attempts = 0;
        loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(3)).await;
            let state = order.refresh().await?;

            match state.status {
                OrderStatus::Ready => {
                    info!("Order is ready for finalization");
                    break;
                }
                OrderStatus::Invalid => {
                    anyhow::bail!("order became invalid");
                }
                OrderStatus::Pending | OrderStatus::Processing => {
                    attempts += 1;
                    if attempts > 30 {
                        anyhow::bail!("timeout waiting for order to become ready");
                    }
                }
                OrderStatus::Valid => {
                    // Should not happen before finalization
                    anyhow::bail!("order became valid before finalization");
                }
            }
        }

        info!("Finalizing order");

        // Generate CSR
        let mut params = rcgen::CertificateParams::new(vec![domain.to_string()])?;
        if wildcard {
            params
                .subject_alt_names
                .push(rcgen::SanType::DnsName(rcgen::Ia5String::try_from(
                    format!("*.{}", domain),
                )?));
        }

        let mut dn = rcgen::DistinguishedName::new();
        dn.push(rcgen::DnType::CommonName, domain);
        params.distinguished_name = dn;

        let key_pair = rcgen::KeyPair::generate()?;
        let csr = params.serialize_request(&key_pair)?;

        // Finalize with CSR
        order.finalize(csr.der()).await?;

        // Poll for certificate
        info!("Polling for certificate");
        let mut attempts = 0;
        let cert_chain = loop {
            tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;

            match order.certificate().await? {
                Some(cert) => {
                    info!("Certificate retrieved");
                    break cert;
                }
                None => {
                    attempts += 1;
                    if attempts > 30 {
                        anyhow::bail!("timeout waiting for certificate");
                    }
                }
            }
        };

        info!("Certificate issued successfully");
        Ok((
            key_pair.serialize_pem().into_bytes(),
            cert_chain.into_bytes(),
        ))
    }

    /// Renew an existing certificate (same as ordering a new one).
    pub async fn renew_certificate(
        &self,
        domain: &str,
        wildcard: bool,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        info!("Renewing certificate for: {}", domain);
        self.order_certificate(domain, wildcard).await
    }
}
