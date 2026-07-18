use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Cloudflare API client for DNS record management.
pub struct CloudflareClient {
    api_token: String,
    client: reqwest::Client,
}

#[derive(Debug, Serialize, Deserialize)]
struct ZoneListResponse {
    result: Vec<Zone>,
    success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Zone {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct CreateRecordRequest {
    r#type: String,
    name: String,
    content: String,
    ttl: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct RecordResponse {
    result: Record,
    success: bool,
}

#[derive(Debug, Serialize, Deserialize)]
struct Record {
    id: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct DeleteResponse {
    success: bool,
}

impl CloudflareClient {
    /// Create a new Cloudflare API client.
    pub fn new(api_token: String) -> Result<Self> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self { api_token, client })
    }

    /// Find the zone ID for a given domain.
    /// Extracts the base domain (e.g., "example.com" from "dns.example.com").
    pub async fn find_zone_id(&self, domain: &str) -> Result<String> {
        // Extract base domain: "dns.example.com" -> "example.com"
        let parts: Vec<&str> = domain.split('.').collect();
        let base_domain = if parts.len() > 2 {
            parts[parts.len() - 2..].join(".")
        } else {
            domain.to_string()
        };

        let url = format!(
            "https://api.cloudflare.com/client/v4/zones?name={}",
            base_domain
        );

        let response = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .context("failed to query Cloudflare zones")?;

        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if !status.is_success() {
            anyhow::bail!("Cloudflare API error ({}): {}", status, body);
        }

        let zone_list: ZoneListResponse =
            serde_json::from_str(&body).context("failed to parse zone list response")?;

        if !zone_list.success {
            anyhow::bail!("Cloudflare zone lookup failed (success=false): {body}");
        }
        match zone_list.result.first() {
            Some(zone) => Ok(zone.id.clone()),
            None => anyhow::bail!("zone not found for domain: {}", domain),
        }
    }

    /// Create a TXT record for ACME DNS-01 challenge.
    /// Returns the record ID.
    pub async fn create_txt_record(
        &self,
        zone_id: &str,
        name: &str,
        value: &str,
    ) -> Result<String> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records",
            zone_id
        );

        let request = CreateRecordRequest {
            r#type: "TXT".to_string(),
            name: name.to_string(),
            content: value.to_string(),
            ttl: 120, // 2 minutes for fast propagation
        };

        let response = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .json(&request)
            .send()
            .await
            .context("failed to create TXT record")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Cloudflare API error ({}): {}", status, body);
        }

        let record_response: RecordResponse = response
            .json()
            .await
            .context("failed to parse record creation response")?;

        if !record_response.success {
            anyhow::bail!("failed to create TXT record");
        }

        Ok(record_response.result.id)
    }

    /// Delete a DNS record by ID.
    pub async fn delete_txt_record(&self, zone_id: &str, record_id: &str) -> Result<()> {
        let url = format!(
            "https://api.cloudflare.com/client/v4/zones/{}/dns_records/{}",
            zone_id, record_id
        );

        let response = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .context("failed to delete TXT record")?;

        let status = response.status();
        if !status.is_success() {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("Cloudflare API error ({}): {}", status, body);
        }

        let delete_response: DeleteResponse = response
            .json()
            .await
            .context("failed to parse delete response")?;

        if !delete_response.success {
            anyhow::bail!("failed to delete TXT record");
        }

        Ok(())
    }
}
