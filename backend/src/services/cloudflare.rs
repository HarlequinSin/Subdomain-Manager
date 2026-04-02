use super::provider::{DnsProvider, DnsRecordDesired, DnsRecordManaged};
use serde::{Deserialize, Serialize};

#[derive(Clone)]
pub struct CloudflareProvider {
    client: reqwest::Client,
    api_token: String,
}

impl CloudflareProvider {
    pub fn new(client: reqwest::Client, api_token: impl Into<String>) -> Self {
        Self {
            client,
            api_token: api_token.into(),
        }
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.api_token)
    }

    fn endpoint(&self, zone_id: &str, record_id: Option<&str>) -> String {
        if let Some(record_id) = record_id {
            format!(
                "https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records/{record_id}"
            )
        } else {
            format!("https://api.cloudflare.com/client/v4/zones/{zone_id}/dns_records")
        }
    }

    fn to_payload(record: &DnsRecordDesired) -> CloudflareDnsRecordRequest {
        let srv_data = if record.record_type == "SRV" {
            let (service, protocol, srv_name) = parse_srv_name_parts(
                &record.name,
                record.service.as_deref(),
                record.protocol.as_deref(),
            );

            Some(CloudflareSrvRecordRequestData {
                service,
                proto: protocol,
                name: srv_name,
                priority: record.priority.unwrap_or(0),
                weight: record.weight.unwrap_or(0),
                port: record.port.unwrap_or(25565),
                target: record.content.clone(),
            })
        } else {
            None
        };

        CloudflareDnsRecordRequest {
            r#type: record.record_type.clone(),
            name: record.name.clone(),
            content: if record.record_type == "SRV" {
                None
            } else {
                Some(record.content.clone())
            },
            ttl: Some(record.ttl),
            proxied: record.proxied,
            priority: record.priority,
            data: srv_data,
        }
    }

    fn from_result(result: CloudflareDnsRecordResponse) -> DnsRecordManaged {
        let content = if result.r#type == "SRV" {
            result
                .data
                .as_ref()
                .and_then(|d| d.target.clone())
                .or(result.content.clone())
                .unwrap_or_default()
        } else {
            result.content.clone().unwrap_or_default()
        };

        DnsRecordManaged {
            id: result.id,
            record_type: result.r#type,
            name: result.name,
            content,
            ttl: result.ttl.unwrap_or(1),
            proxied: result.proxied,
            priority: result.priority,
            port: result.data.as_ref().and_then(|d| d.port),
            weight: result.data.as_ref().and_then(|d| d.weight),
            service: result.data.as_ref().and_then(|d| d.service.clone()),
            protocol: result.data.as_ref().and_then(|d| d.proto.clone()),
        }
    }

    fn cloudflare_error_message(errors: &[CloudflareError]) -> String {
        if errors.is_empty() {
            return "unknown Cloudflare API error".to_string();
        }

        errors
            .iter()
            .map(|err| {
                let code = err.code.map(|code| format!("code={code}, ")).unwrap_or_default();
                format!("{code}message={}", err.message)
            })
            .collect::<Vec<_>>()
            .join("; ")
    }

    pub async fn verify_token(&self) -> Result<(), anyhow::Error> {
        let response = self
            .client
            .get("https://api.cloudflare.com/client/v4/user/tokens/verify")
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        let status = response.status();
        let body: CloudflareResponse<CloudflareTokenVerifyResult> = response.json().await?;

        if !status.is_success() || !body.success {
            let message = Self::cloudflare_error_message(&body.errors);
            return Err(anyhow::anyhow!(
                "cloudflare token verification failed: {message}"
            ));
        }

        Ok(())
    }

    pub async fn verify_zone_access(&self, zone_id: &str) -> Result<(), anyhow::Error> {
        let response = self
            .client
            .get(format!("https://api.cloudflare.com/client/v4/zones/{zone_id}"))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        let status = response.status();
        let body: CloudflareResponse<CloudflareZoneResult> = response.json().await?;

        if !status.is_success() || !body.success {
            let message = Self::cloudflare_error_message(&body.errors);
            return Err(anyhow::anyhow!(
                "cloudflare zone access verification failed for zone_id={zone_id}: {message}"
            ));
        }

        Ok(())
    }

    pub async fn list_records_by_name_type(
        &self,
        zone_id: &str,
        name: &str,
        record_type: &str,
    ) -> Result<Vec<DnsRecordManaged>, anyhow::Error> {
        let response = self
            .client
            .get(self.endpoint(zone_id, None))
            .header("Authorization", self.auth_header())
            .query(&[
                ("name", name),
                ("type", record_type),
                ("per_page", "100"),
                ("page", "1"),
            ])
            .send()
            .await?;

        let status = response.status();
        let body: CloudflareResponse<Vec<CloudflareDnsRecordResponse>> = response.json().await?;

        if !status.is_success() || !body.success {
            let message = Self::cloudflare_error_message(&body.errors);
            return Err(anyhow::anyhow!(
                "cloudflare list dns records failed: {message}. verify token has Zone.DNS Edit + Zone.Zone Read for the selected zone"
            ));
        }

        Ok(body
            .result
            .unwrap_or_default()
            .into_iter()
            .map(Self::from_result)
            .collect())
    }
}

fn parse_srv_name_parts(
    fqdn_or_srv_name: &str,
    service_override: Option<&str>,
    protocol_override: Option<&str>,
) -> (String, String, String) {
    let mut service = normalize_srv_segment(service_override.unwrap_or("minecraft"));
    let mut protocol = normalize_srv_segment(protocol_override.unwrap_or("tcp"));
    let mut name = fqdn_or_srv_name.to_string();

    let mut parts = fqdn_or_srv_name.splitn(3, '.');
    let first = parts.next();
    let second = parts.next();
    let third = parts.next();

    if let (Some(s), Some(p), Some(rest)) = (first, second, third) {
        if s.starts_with('_') && p.starts_with('_') && !rest.trim().is_empty() {
            service = normalize_srv_segment(s);
            protocol = normalize_srv_segment(p);
            name = rest.to_string();
        }
    }

    (service, protocol, name)
}

fn normalize_srv_segment(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('_') {
        value.to_string()
    } else {
        format!("_{value}")
    }
}

#[async_trait::async_trait]
impl DnsProvider for CloudflareProvider {
    async fn create_record(
        &self,
        zone_id: &str,
        record: &DnsRecordDesired,
    ) -> Result<DnsRecordManaged, anyhow::Error> {
        let response = self
            .client
            .post(self.endpoint(zone_id, None))
            .header("Authorization", self.auth_header())
            .json(&Self::to_payload(record))
            .send()
            .await?;

        let status = response.status();
        let body: CloudflareResponse<CloudflareDnsRecordResponse> = response.json().await?;

        if !status.is_success() || !body.success {
            let message = Self::cloudflare_error_message(&body.errors);
            return Err(anyhow::anyhow!(
                "cloudflare create dns record failed: {message}. verify token has Zone.DNS Edit + Zone.Zone Read for the selected zone"
            ));
        }

        body.result
            .map(Self::from_result)
            .ok_or_else(|| anyhow::anyhow!("cloudflare create dns record returned empty result"))
    }

    async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record: &DnsRecordDesired,
    ) -> Result<DnsRecordManaged, anyhow::Error> {
        let response = self
            .client
            .put(self.endpoint(zone_id, Some(record_id)))
            .header("Authorization", self.auth_header())
            .json(&Self::to_payload(record))
            .send()
            .await?;

        let status = response.status();
        let body: CloudflareResponse<CloudflareDnsRecordResponse> = response.json().await?;

        if !status.is_success() || !body.success {
            let message = Self::cloudflare_error_message(&body.errors);
            return Err(anyhow::anyhow!(
                "cloudflare update dns record failed: {message}. verify token has Zone.DNS Edit + Zone.Zone Read for the selected zone"
            ));
        }

        body.result
            .map(Self::from_result)
            .ok_or_else(|| anyhow::anyhow!("cloudflare update dns record returned empty result"))
    }

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), anyhow::Error> {
        let response = self
            .client
            .delete(self.endpoint(zone_id, Some(record_id)))
            .header("Authorization", self.auth_header())
            .send()
            .await?;

        let status = response.status();
        let body: CloudflareResponse<serde_json::Value> = response.json().await?;

        if !status.is_success() || !body.success {
            let message = Self::cloudflare_error_message(&body.errors);
            return Err(anyhow::anyhow!(
                "cloudflare delete dns record failed: {message}. verify token has Zone.DNS Edit + Zone.Zone Read for the selected zone"
            ));
        }

        Ok(())
    }
}

#[derive(Serialize)]
struct CloudflareDnsRecordRequest {
    #[serde(rename = "type")]
    r#type: String,
    name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ttl: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proxied: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    priority: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<CloudflareSrvRecordRequestData>,
}

#[derive(Serialize, Deserialize, Clone)]
struct CloudflareSrvRecordRequestData {
    service: String,
    #[serde(rename = "proto")]
    proto: String,
    name: String,
    priority: i32,
    weight: i32,
    port: i32,
    target: String,
}

#[derive(Deserialize, Clone)]
struct CloudflareSrvRecordResponseData {
    #[serde(default)]
    service: Option<String>,
    #[serde(rename = "proto", default)]
    proto: Option<String>,
    #[serde(default)]
    weight: Option<i32>,
    #[serde(default)]
    port: Option<i32>,
    #[serde(default)]
    target: Option<String>,
}

#[derive(Deserialize)]
struct CloudflareResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CloudflareError>,
    result: Option<T>,
}

#[derive(Deserialize)]
struct CloudflareError {
    code: Option<i64>,
    message: String,
}

#[derive(Deserialize)]
struct CloudflareDnsRecordResponse {
    id: String,
    #[serde(rename = "type")]
    r#type: String,
    name: String,
    content: Option<String>,
    ttl: Option<i32>,
    proxied: Option<bool>,
    priority: Option<i32>,
    data: Option<CloudflareSrvRecordResponseData>,
}

#[derive(Deserialize)]
struct CloudflareTokenVerifyResult {
    #[allow(dead_code)]
    id: Option<String>,
}

#[derive(Deserialize)]
struct CloudflareZoneResult {
    #[allow(dead_code)]
    id: Option<String>,
}
