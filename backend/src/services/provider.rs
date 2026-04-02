use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct DnsRecordDesired {
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: i32,
    pub proxied: Option<bool>,
    pub priority: Option<i32>,
    pub port: Option<i32>,
    pub weight: Option<i32>,
    pub service: Option<String>,
    pub protocol: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct DnsRecordManaged {
    pub id: String,
    pub record_type: String,
    pub name: String,
    pub content: String,
    pub ttl: i32,
    pub proxied: Option<bool>,
    pub priority: Option<i32>,
    pub port: Option<i32>,
    pub weight: Option<i32>,
    pub service: Option<String>,
    pub protocol: Option<String>,
}

#[async_trait::async_trait]
pub trait DnsProvider: Send + Sync {
    async fn create_record(
        &self,
        zone_id: &str,
        record: &DnsRecordDesired,
    ) -> Result<DnsRecordManaged, anyhow::Error>;

    async fn update_record(
        &self,
        zone_id: &str,
        record_id: &str,
        record: &DnsRecordDesired,
    ) -> Result<DnsRecordManaged, anyhow::Error>;

    async fn delete_record(&self, zone_id: &str, record_id: &str) -> Result<(), anyhow::Error>;
}
