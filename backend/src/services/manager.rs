use crate::{
    models::{
        AdminConfigResponse, ApiAliasRule, ApiAssignment, ApiBlacklistRule, ApiGeneratedRecord,
        ApiManagedDomain, ApiProvider, ApiRecordTemplate, AssignmentStatus,
        PutClientAssignmentRequest,
    },
    validation,
};
use regex::Regex;
use shared::models::server::Server;
use sqlx::Row;
use std::collections::HashMap;
use std::str::FromStr;

use super::{
    cloudflare::CloudflareProvider,
    provider::{DnsProvider, DnsRecordDesired, DnsRecordManaged},
};

pub async fn get_admin_config(state: &shared::State) -> Result<AdminConfigResponse, anyhow::Error> {
    let providers = sqlx::query(
        r#"
        SELECT uuid, name, provider_type, enabled, created, updated
        FROM ext_cloudflare_subdomain_providers
        ORDER BY created
        "#,
    )
    .fetch_all(state.database.read())
    .await?
    .into_iter()
    .map(|row| ApiProvider {
        uuid: row.get("uuid"),
        name: row.get::<String, _>("name"),
        provider_type: row.get::<String, _>("provider_type"),
        enabled: row.get("enabled"),
        created: row.get::<chrono::NaiveDateTime, _>("created").and_utc(),
        updated: row.get::<chrono::NaiveDateTime, _>("updated").and_utc(),
    })
    .collect::<Vec<_>>();

    let managed_domains = list_managed_domains(state).await?;
    let blacklist_rules = list_blacklist_rules(state).await?;
    let alias_rules = list_alias_rules(state).await?;
    let record_templates = list_record_templates(state).await?;

    Ok(AdminConfigResponse {
        providers,
        managed_domains,
        blacklist_rules,
        alias_rules,
        record_templates,
    })
}

pub async fn upsert_provider(
    state: &shared::State,
    name: &str,
    api_token: &str,
    enabled: bool,
) -> Result<ApiProvider, anyhow::Error> {
    let mut api_token = api_token.trim().to_string();
    if let Some(stripped) = api_token.strip_prefix("Bearer ") {
        api_token = stripped.trim().to_string();
    }

    let api_token = api_token.as_str();
    if api_token.is_empty() {
        return Err(anyhow::anyhow!("api token cannot be empty"));
    }

    let provider = CloudflareProvider::new(state.client.clone(), api_token.to_owned());
    provider.verify_token().await?;

    let encrypted = state.database.encrypt(api_token.to_owned()).await?;

    let row = sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_providers (name, provider_type, api_token_encrypted, enabled)
        VALUES ($1, 'cloudflare', $2, $3)
        ON CONFLICT (name)
        DO UPDATE SET api_token_encrypted = EXCLUDED.api_token_encrypted, enabled = EXCLUDED.enabled, updated = NOW()
        RETURNING uuid, name, provider_type, enabled, created, updated
        "#,
    )
    .bind(name)
    .bind(encrypted)
    .bind(enabled)
    .fetch_one(state.database.write())
    .await?;

    Ok(ApiProvider {
        uuid: row.get("uuid"),
        name: row.get("name"),
        provider_type: row.get("provider_type"),
        enabled: row.get("enabled"),
        created: row.get::<chrono::NaiveDateTime, _>("created").and_utc(),
        updated: row.get::<chrono::NaiveDateTime, _>("updated").and_utc(),
    })
}

pub async fn upsert_managed_domain(
    state: &shared::State,
    provider_uuid: uuid::Uuid,
    display_name: &str,
    base_domain: &str,
    zone_name: &str,
    zone_id: &str,
    default_ttl: i32,
    default_proxied: bool,
    game: Option<&str>,
    allow_user_updates: bool,
    allowed_record_types: &[String],
) -> Result<ApiManagedDomain, anyhow::Error> {
    let display_name = display_name.trim();
    let base_domain = base_domain.trim().trim_matches('.').to_lowercase();
    let zone_name = zone_name.trim().trim_matches('.').to_lowercase();
    let zone_id = zone_id.trim().to_lowercase();

    if !Regex::new(r"^[a-f0-9]{32}$")
        .expect("zone id regex must compile")
        .is_match(&zone_id)
    {
        return Err(anyhow::anyhow!(
            "invalid zone_id format: expected 32 lowercase hex characters from Cloudflare"
        ));
    }

    let provider_row = sqlx::query(
        r#"
        SELECT api_token_encrypted
        FROM ext_cloudflare_subdomain_providers
        WHERE uuid = $1 AND enabled
        "#,
    )
    .bind(provider_uuid)
    .fetch_optional(state.database.read())
    .await?
    .ok_or_else(|| anyhow::anyhow!("provider not found or disabled"))?;

    let token_encrypted: Vec<u8> = provider_row.get("api_token_encrypted");
    let api_token = state.database.decrypt(token_encrypted).await?;
    let provider = CloudflareProvider::new(state.client.clone(), api_token.to_string());
    provider.verify_zone_access(&zone_id).await?;

    let row = sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_managed_domains (
            provider_uuid, display_name, base_domain, zone_name, zone_id,
            default_ttl, default_proxied, game, allow_user_updates, allowed_record_types
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
        ON CONFLICT (base_domain)
        DO UPDATE SET
            provider_uuid = EXCLUDED.provider_uuid,
            display_name = EXCLUDED.display_name,
            zone_name = EXCLUDED.zone_name,
            zone_id = EXCLUDED.zone_id,
            default_ttl = EXCLUDED.default_ttl,
            default_proxied = EXCLUDED.default_proxied,
            game = EXCLUDED.game,
            allow_user_updates = EXCLUDED.allow_user_updates,
            allowed_record_types = EXCLUDED.allowed_record_types,
            updated = NOW()
        RETURNING uuid, provider_uuid, display_name, base_domain, zone_name, zone_id, default_ttl,
                  default_proxied, game, allow_user_updates, allowed_record_types
        "#,
    )
    .bind(provider_uuid)
    .bind(display_name)
    .bind(base_domain)
    .bind(zone_name)
    .bind(zone_id)
    .bind(default_ttl)
    .bind(default_proxied)
    .bind(game)
    .bind(allow_user_updates)
    .bind(allowed_record_types)
    .fetch_one(state.database.write())
    .await?;

    Ok(map_managed_domain_row(&row)?)
}

pub async fn upsert_blacklist_rule(
    state: &shared::State,
    managed_domain_uuid: Option<uuid::Uuid>,
    pattern: &str,
    case_sensitive: bool,
    enabled: bool,
    description: Option<&str>,
) -> Result<ApiBlacklistRule, anyhow::Error> {
    let row = sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_blacklist_rules (managed_domain_uuid, pattern, case_sensitive, enabled, description)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (managed_domain_uuid, pattern)
        DO UPDATE SET case_sensitive = EXCLUDED.case_sensitive, enabled = EXCLUDED.enabled,
            description = EXCLUDED.description, updated = NOW()
        RETURNING uuid, managed_domain_uuid, pattern, case_sensitive, enabled, description
        "#,
    )
    .bind(managed_domain_uuid)
    .bind(pattern)
    .bind(case_sensitive)
    .bind(enabled)
    .bind(description)
    .fetch_one(state.database.write())
    .await?;

    Ok(ApiBlacklistRule {
        uuid: row.get("uuid"),
        managed_domain_uuid: row.get("managed_domain_uuid"),
        pattern: row.get("pattern"),
        case_sensitive: row.get("case_sensitive"),
        enabled: row.get("enabled"),
        description: row.get("description"),
    })
}

pub async fn upsert_alias_rule(
    state: &shared::State,
    managed_domain_uuid: Option<uuid::Uuid>,
    source: &str,
    target: &str,
    enabled: bool,
) -> Result<ApiAliasRule, anyhow::Error> {
    let row = sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_alias_rules (managed_domain_uuid, source, target, enabled)
        VALUES ($1, $2, $3, $4)
        ON CONFLICT (managed_domain_uuid, source)
        DO UPDATE SET target = EXCLUDED.target, enabled = EXCLUDED.enabled, updated = NOW()
        RETURNING uuid, managed_domain_uuid, source, target, enabled
        "#,
    )
    .bind(managed_domain_uuid)
    .bind(source)
    .bind(target)
    .bind(enabled)
    .fetch_one(state.database.write())
    .await?;

    Ok(ApiAliasRule {
        uuid: row.get("uuid"),
        managed_domain_uuid: row.get("managed_domain_uuid"),
        source: row.get("source"),
        target: row.get("target"),
        enabled: row.get("enabled"),
    })
}

#[allow(clippy::too_many_arguments)]
pub async fn upsert_record_template(
    state: &shared::State,
    managed_domain_uuid: uuid::Uuid,
    egg_uuid: Option<uuid::Uuid>,
    game: Option<&str>,
    record_type: &str,
    content_template: &str,
    ttl: Option<i32>,
    proxied: Option<bool>,
    priority: Option<i32>,
    weight: Option<i32>,
    port: Option<i32>,
    service: Option<&str>,
    protocol: Option<&str>,
    only_non_default_port: bool,
    enabled: bool,
) -> Result<ApiRecordTemplate, anyhow::Error> {
    let row = sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_record_templates (
            managed_domain_uuid, egg_uuid, game, record_type, content_template,
            ttl, proxied, priority, weight, port, service, protocol,
            only_non_default_port, enabled
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)
        RETURNING uuid, managed_domain_uuid, egg_uuid, game, record_type, content_template,
                  ttl, proxied, priority, weight, port, service, protocol, only_non_default_port, enabled
        "#,
    )
    .bind(managed_domain_uuid)
    .bind(egg_uuid)
    .bind(game)
    .bind(record_type)
    .bind(content_template)
    .bind(ttl)
    .bind(proxied)
    .bind(priority)
    .bind(weight)
    .bind(port)
    .bind(service)
    .bind(protocol)
    .bind(only_non_default_port)
    .bind(enabled)
    .fetch_one(state.database.write())
    .await?;

    Ok(ApiRecordTemplate {
        uuid: row.get("uuid"),
        managed_domain_uuid: row.get("managed_domain_uuid"),
        egg_uuid: row.get("egg_uuid"),
        game: row.get("game"),
        record_type: row.get("record_type"),
        content_template: row.get("content_template"),
        ttl: row.get("ttl"),
        proxied: row.get("proxied"),
        priority: row.get("priority"),
        weight: row.get("weight"),
        port: row.get("port"),
        service: row.get("service"),
        protocol: row.get("protocol"),
        only_non_default_port: row.get("only_non_default_port"),
        enabled: row.get("enabled"),
    })
}

pub async fn list_managed_domains(
    state: &shared::State,
) -> Result<Vec<ApiManagedDomain>, anyhow::Error> {
    let rows = sqlx::query(
        r#"
        SELECT uuid, provider_uuid, display_name, base_domain, zone_name, zone_id,
               default_ttl, default_proxied, game, allow_user_updates, allowed_record_types
        FROM ext_cloudflare_subdomain_managed_domains
        WHERE enabled
        ORDER BY base_domain
        "#,
    )
    .fetch_all(state.database.read())
    .await?;

    rows.iter().map(map_managed_domain_row).collect()
}

pub async fn list_blacklist_rules(
    state: &shared::State,
) -> Result<Vec<ApiBlacklistRule>, anyhow::Error> {
    let rows = sqlx::query(
        r#"
        SELECT uuid, managed_domain_uuid, pattern, case_sensitive, enabled, description
        FROM ext_cloudflare_subdomain_blacklist_rules
        WHERE enabled
        ORDER BY created
        "#,
    )
    .fetch_all(state.database.read())
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ApiBlacklistRule {
            uuid: row.get("uuid"),
            managed_domain_uuid: row.get("managed_domain_uuid"),
            pattern: row.get("pattern"),
            case_sensitive: row.get("case_sensitive"),
            enabled: row.get("enabled"),
            description: row.get("description"),
        })
        .collect())
}

pub async fn list_alias_rules(state: &shared::State) -> Result<Vec<ApiAliasRule>, anyhow::Error> {
    let rows = sqlx::query(
        r#"
        SELECT uuid, managed_domain_uuid, source, target, enabled
        FROM ext_cloudflare_subdomain_alias_rules
        WHERE enabled
        ORDER BY source
        "#,
    )
    .fetch_all(state.database.read())
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ApiAliasRule {
            uuid: row.get("uuid"),
            managed_domain_uuid: row.get("managed_domain_uuid"),
            source: row.get("source"),
            target: row.get("target"),
            enabled: row.get("enabled"),
        })
        .collect())
}

pub async fn list_record_templates(
    state: &shared::State,
) -> Result<Vec<ApiRecordTemplate>, anyhow::Error> {
    let rows = sqlx::query(
        r#"
        SELECT uuid, managed_domain_uuid, egg_uuid, game, record_type, content_template,
               ttl, proxied, priority, weight, port, service, protocol, only_non_default_port, enabled
        FROM ext_cloudflare_subdomain_record_templates
        WHERE enabled
        ORDER BY created
        "#,
    )
    .fetch_all(state.database.read())
    .await?;

    Ok(rows
        .into_iter()
        .map(|row| ApiRecordTemplate {
            uuid: row.get("uuid"),
            managed_domain_uuid: row.get("managed_domain_uuid"),
            egg_uuid: row.get("egg_uuid"),
            game: row.get("game"),
            record_type: row.get("record_type"),
            content_template: row.get("content_template"),
            ttl: row.get("ttl"),
            proxied: row.get("proxied"),
            priority: row.get("priority"),
            weight: row.get("weight"),
            port: row.get("port"),
            service: row.get("service"),
            protocol: row.get("protocol"),
            only_non_default_port: row.get("only_non_default_port"),
            enabled: row.get("enabled"),
        })
        .collect())
}

pub async fn get_client_assignment(
    state: &shared::State,
    server_uuid: uuid::Uuid,
) -> Result<Option<ApiAssignment>, anyhow::Error> {
    get_assignment(state, server_uuid).await
}

pub async fn assign_server_subdomain(
    state: &shared::State,
    server: &Server,
    request: PutClientAssignmentRequest,
) -> Result<ApiAssignment, anyhow::Error> {
    let label = validation::normalize_label(&request.label);
    validation::validate_label(&label)?;

    let record_type = resolve_record_type_for_server_type(&request)?;
    validation::validate_record_type(&record_type)?;

    let managed_domain = sqlx::query(
        r#"
        SELECT uuid, provider_uuid, display_name, base_domain, zone_name, zone_id,
               default_ttl, default_proxied, game, allow_user_updates, allowed_record_types
        FROM ext_cloudflare_subdomain_managed_domains
        WHERE uuid = $1 AND enabled
        "#,
    )
    .bind(request.managed_domain_uuid)
    .fetch_optional(state.database.read())
    .await?
    .ok_or_else(|| anyhow::anyhow!("managed domain not found"))?;

    let allow_updates: bool = managed_domain.get("allow_user_updates");
    if !allow_updates {
        let existing = get_assignment(state, server.uuid).await?;
        if existing.is_some() {
            return Err(anyhow::anyhow!(
                "subdomain updates are disabled for the selected managed domain"
            ));
        }
    }

    let allowed_record_types: Vec<String> = managed_domain.get("allowed_record_types");
    if !allowed_record_types.iter().any(|t| t == &record_type) {
        return Err(anyhow::anyhow!(
            "selected record type is not allowed in this managed domain"
        ));
    }

    let base_domain: String = managed_domain.get("base_domain");
    let fqdn = format!("{label}.{base_domain}");

    ensure_not_blacklisted(state, managed_domain.get("uuid"), &label).await?;

    let allocation = load_server_allocation_target(state, server, request.allocation_uuid).await?;
    let source = resolve_target_source(state, server, &allocation).await?;

    let resolved_target = resolve_target_from_alias(
        state,
        managed_domain.get("uuid"),
        source.as_deref(),
    )
    .await?;

    sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_assignments (
            server_uuid, managed_domain_uuid, record_type, label, fqdn, status,
            assignment_source, allocation_ip, allocation_ip_alias, allocation_port, resolved_target
        )
        VALUES ($1, $2, $3, $4, $5, $6, 'user', $7, $8, $9, $10)
        ON CONFLICT (server_uuid)
        DO UPDATE SET
            managed_domain_uuid = EXCLUDED.managed_domain_uuid,
            record_type = EXCLUDED.record_type,
            label = EXCLUDED.label,
            fqdn = EXCLUDED.fqdn,
            status = EXCLUDED.status,
            assignment_source = EXCLUDED.assignment_source,
            allocation_ip = EXCLUDED.allocation_ip,
            allocation_ip_alias = EXCLUDED.allocation_ip_alias,
            allocation_port = EXCLUDED.allocation_port,
            resolved_target = EXCLUDED.resolved_target,
            updated = NOW()
        "#,
    )
    .bind(server.uuid)
    .bind(request.managed_domain_uuid)
    .bind(&record_type)
    .bind(&label)
    .bind(&fqdn)
    .bind(AssignmentStatus::Assigned.as_str())
    .bind(allocation.as_ref().and_then(|a| a.ip.as_deref()))
    .bind(allocation.as_ref().and_then(|a| a.ip_alias.as_deref()))
    .bind(allocation.as_ref().map(|a| a.port))
    .bind(resolved_target.as_deref())
    .execute(state.database.write())
    .await?;

    create_audit_event(
        state,
        server.uuid,
        "assignment.create_or_update",
        serde_json::json!({
            "fqdn": fqdn,
            "record_type": record_type,
            "managed_domain_uuid": request.managed_domain_uuid,
            "dry_run": request.dry_run,
        }),
    )
    .await?;

    if !request.dry_run {
        reconcile_server_assignment(state, server.uuid, false).await?;
    }

    get_assignment(state, server.uuid)
        .await?
        .ok_or_else(|| anyhow::anyhow!("assignment not found after update"))
}

fn resolve_record_type_for_server_type(
    request: &PutClientAssignmentRequest,
) -> Result<String, anyhow::Error> {
    if let Some(server_type) = request.server_type.as_deref() {
        return match server_type.trim().to_lowercase().as_str() {
            "minecraft" => Ok("SRV".to_string()),
            "web" => Ok("A".to_string()),
            _ => Err(anyhow::anyhow!(
                "unsupported server type. allowed values are: minecraft, web"
            )),
        };
    }

    Ok(validation::normalize_record_type(&request.record_type))
}

pub async fn clear_server_assignment(
    state: &shared::State,
    server_uuid: uuid::Uuid,
) -> Result<(), anyhow::Error> {
    cleanup_managed_records_for_server(state, server_uuid).await?;

    sqlx::query(
        r#"
        DELETE FROM ext_cloudflare_subdomain_assignments
        WHERE server_uuid = $1
        "#,
    )
    .bind(server_uuid)
    .execute(state.database.write())
    .await?;

    create_audit_event(
        state,
        server_uuid,
        "assignment.delete",
        serde_json::json!({ "server_uuid": server_uuid }),
    )
    .await?;

    Ok(())
}

pub async fn mark_assignment_unknown(
    state: &shared::State,
    server_uuid: uuid::Uuid,
    reason: &str,
) -> Result<(), anyhow::Error> {
    sqlx::query(
        r#"
        UPDATE ext_cloudflare_subdomain_assignments
        SET status = $2, allocation_ip = NULL, allocation_ip_alias = NULL,
            allocation_port = NULL, resolved_target = NULL, updated = NOW()
        WHERE server_uuid = $1
        "#,
    )
    .bind(server_uuid)
    .bind(AssignmentStatus::Unknown.as_str())
    .execute(state.database.write())
    .await?;

    create_audit_event(
        state,
        server_uuid,
        "assignment.transfer_unknown",
        serde_json::json!({ "reason": reason }),
    )
    .await?;

    Ok(())
}

pub async fn reconcile_server_assignment(
    state: &shared::State,
    server_uuid: uuid::Uuid,
    dry_run: bool,
) -> Result<Option<ApiAssignment>, anyhow::Error> {
    let assignment_row = sqlx::query(
        r#"
        SELECT a.uuid, a.server_uuid, a.managed_domain_uuid, a.record_type, a.label, a.fqdn,
               a.status, a.assignment_source, a.allocation_ip, a.allocation_ip_alias, a.allocation_port,
               a.resolved_target, a.created, a.updated,
               d.zone_id, d.default_ttl, d.default_proxied, d.base_domain,
               p.api_token_encrypted
        FROM ext_cloudflare_subdomain_assignments a
        JOIN ext_cloudflare_subdomain_managed_domains d ON d.uuid = a.managed_domain_uuid
        JOIN ext_cloudflare_subdomain_providers p ON p.uuid = d.provider_uuid
        WHERE a.server_uuid = $1
        "#,
    )
    .bind(server_uuid)
    .fetch_optional(state.database.read())
    .await?;

    let Some(assignment_row) = assignment_row else {
        return Ok(None);
    };

    let assignment_uuid: uuid::Uuid = assignment_row.get("uuid");
    let zone_id: String = assignment_row.get("zone_id");
    let default_ttl: i32 = assignment_row.get("default_ttl");
    let default_proxied: bool = assignment_row.get("default_proxied");
    let token_encrypted: Vec<u8> = assignment_row.get("api_token_encrypted");
    let api_token = state.database.decrypt(token_encrypted).await?;

    let provider = CloudflareProvider::new(state.client.clone(), api_token);

    let allocation_port: Option<i32> = assignment_row.get("allocation_port");

    let base_record_type: String = assignment_row.get("record_type");
    let base_fqdn: String = assignment_row.get("fqdn");

    let mut desired = vec![DnsRecordDesired {
        record_type: base_record_type.clone(),
        name: build_record_name(&base_record_type, &base_fqdn, None, None),
        content: resolve_assignment_content(&assignment_row),
        ttl: default_ttl,
        proxied: Some(default_proxied),
        priority: None,
        port: allocation_port,
        weight: None,
        service: None,
        protocol: None,
    }];

    let template_rows = sqlx::query(
        r#"
        SELECT t.record_type, t.content_template, t.ttl, t.proxied, t.priority, t.weight, t.port,
               t.service, t.protocol, t.only_non_default_port, s.egg_uuid
        FROM ext_cloudflare_subdomain_record_templates t
        JOIN servers s ON s.uuid = $1
        WHERE t.managed_domain_uuid = $2 AND t.enabled
            AND (t.egg_uuid IS NULL OR t.egg_uuid = s.egg_uuid)
        ORDER BY t.created
        "#,
    )
    .bind(server_uuid)
    .bind(assignment_row.get::<uuid::Uuid, _>("managed_domain_uuid"))
    .fetch_all(state.database.read())
    .await?;

    for row in template_rows {
        let only_non_default_port: bool = row.get("only_non_default_port");
        if only_non_default_port && allocation_port.is_some_and(|p| p == 25565) {
            continue;
        }

        let content_template: String = row.get("content_template");
        let content = render_template(
            &content_template,
            &TemplateContext {
                label: assignment_row.get("label"),
                fqdn: assignment_row.get("fqdn"),
                base_domain: assignment_row.get("base_domain"),
                ip: assignment_row.get::<Option<String>, _>("allocation_ip"),
                ip_alias: assignment_row.get::<Option<String>, _>("allocation_ip_alias"),
                target: assignment_row.get::<Option<String>, _>("resolved_target"),
                port: assignment_row.get::<Option<i32>, _>("allocation_port"),
                server_uuid,
            },
        );

        let template_record_type: String = row.get("record_type");
        let template_service: Option<String> = row.get("service");
        let template_protocol: Option<String> = row.get("protocol");
        let fqdn: String = assignment_row.get("fqdn");

        desired.push(DnsRecordDesired {
            record_type: template_record_type.clone(),
            name: build_record_name(
                &template_record_type,
                &fqdn,
                template_service.as_deref(),
                template_protocol.as_deref(),
            ),
            content,
            ttl: row.get::<Option<i32>, _>("ttl").unwrap_or(default_ttl),
            proxied: row.get::<Option<bool>, _>("proxied").or(Some(default_proxied)),
            priority: row.get("priority"),
            port: row.get::<Option<i32>, _>("port").or(allocation_port),
            weight: row.get("weight"),
            service: template_service,
            protocol: template_protocol,
        });
    }

    for record in &mut desired {
        validate_desired_record(record)?;
    }

    let existing_rows = sqlx::query(
        r#"
        SELECT uuid, cloudflare_record_id, record_type, name, content, ttl, proxied,
               priority, port, weight, service, protocol
        FROM ext_cloudflare_subdomain_generated_records
        WHERE assignment_uuid = $1
        ORDER BY created
        "#,
    )
    .bind(assignment_uuid)
    .fetch_all(state.database.read())
    .await?;
    let mut existing_by_key: HashMap<String, sqlx::postgres::PgRow> = HashMap::new();
    for row in existing_rows {
        existing_by_key.insert(record_key_from_row(&row), row);
    }

    for record in &desired {
        let key = record_key(record);
        let existing = existing_by_key.remove(&key);

        let managed_record = if dry_run {
            None
        } else {
            match existing.as_ref().and_then(|r| r.get::<Option<String>, _>("cloudflare_record_id")) {
                Some(record_id) => Some(provider.update_record(&zone_id, &record_id, record).await?),
                None => Some(provider.create_record(&zone_id, record).await?),
            }
        };

        if !dry_run {
            upsert_generated_record(state, assignment_uuid, record, managed_record.as_ref()).await?;
        }
    }

    for obsolete in existing_by_key.into_values() {
        let record_uuid: uuid::Uuid = obsolete.get("uuid");
        let cloudflare_record_id: Option<String> = obsolete.get("cloudflare_record_id");

        if !dry_run {
            if let Some(record_id) = cloudflare_record_id {
                provider.delete_record(&zone_id, &record_id).await?;
            }

            sqlx::query(
                r#"
                DELETE FROM ext_cloudflare_subdomain_generated_records
                WHERE uuid = $1
                "#,
            )
            .bind(record_uuid)
            .execute(state.database.write())
            .await?;
        }
    }

    create_audit_event(
        state,
        server_uuid,
        "assignment.reconcile",
        serde_json::json!({
            "dry_run": dry_run,
            "desired_records": desired.len(),
        }),
    )
    .await?;

    get_assignment(state, server_uuid).await
}

pub async fn cleanup_managed_records_for_server(
    state: &shared::State,
    server_uuid: uuid::Uuid,
) -> Result<(), anyhow::Error> {
    let assignment = sqlx::query(
        r#"
        SELECT a.uuid AS assignment_uuid, a.fqdn, a.record_type, d.zone_id
        FROM ext_cloudflare_subdomain_assignments a
        JOIN ext_cloudflare_subdomain_managed_domains d ON d.uuid = a.managed_domain_uuid
        WHERE a.server_uuid = $1
        "#,
    )
    .bind(server_uuid)
    .fetch_optional(state.database.read())
    .await?;

    let Some(assignment) = assignment else {
        return Ok(());
    };

    let assignment_uuid: uuid::Uuid = assignment.get("assignment_uuid");
    let assignment_fqdn: String = assignment.get("fqdn");
    let assignment_record_type: String = assignment.get("record_type");
    let zone_id: String = assignment.get("zone_id");

    let provider = load_provider_for_server(state, server_uuid).await?;

    let rows = sqlx::query(
        r#"
        SELECT r.uuid, r.cloudflare_record_id, r.record_type, r.name
        FROM ext_cloudflare_subdomain_generated_records r
        WHERE r.assignment_uuid = $1
        "#,
    )
    .bind(assignment_uuid)
    .fetch_all(state.database.read())
    .await?;
    let no_tracked_rows = rows.is_empty();

    let mut deleted_remote = 0usize;

    for row in rows {
        let record_uuid: uuid::Uuid = row.get("uuid");
        let record_name: String = row.get("name");
        let record_type: String = row.get("record_type");

        if let Some(record_id) = row.get::<Option<String>, _>("cloudflare_record_id") {
            if let Some(provider) = provider.as_ref() {
                let _ = provider.delete_record(&zone_id, &record_id).await;
                deleted_remote += 1;
            }
        } else if let Some(provider) = provider.as_ref() {
            let records = provider
                .list_records_by_name_type(&zone_id, &record_name, &record_type)
                .await
                .unwrap_or_default();

            for remote in records {
                let _ = provider.delete_record(&zone_id, &remote.id).await;
                deleted_remote += 1;
            }
        }

        sqlx::query(
            r#"
            DELETE FROM ext_cloudflare_subdomain_generated_records
            WHERE uuid = $1
            "#,
        )
        .bind(record_uuid)
        .execute(state.database.write())
        .await?;
    }

    if no_tracked_rows {
        if let Some(provider) = provider.as_ref() {
            let mut fallback_names = vec![assignment_fqdn.clone()];

            if assignment_record_type == "SRV" {
                fallback_names.push(format!("_minecraft._tcp.{}", assignment_fqdn));
            }

            for name in fallback_names {
                let records = provider
                    .list_records_by_name_type(&zone_id, &name, &assignment_record_type)
                    .await
                    .unwrap_or_default();

                for remote in records {
                    let _ = provider.delete_record(&zone_id, &remote.id).await;
                    deleted_remote += 1;
                }
            }
        }
    }

    create_audit_event(
        state,
        server_uuid,
        "assignment.cleanup",
        serde_json::json!({
            "server_uuid": server_uuid,
            "deleted_remote_records": deleted_remote
        }),
    )
    .await?;

    Ok(())
}

pub async fn create_audit_event(
    state: &shared::State,
    server_uuid: uuid::Uuid,
    event: &str,
    payload: serde_json::Value,
) -> Result<(), anyhow::Error> {
    sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_audit_events (server_uuid, event, payload)
        VALUES ($1, $2, $3)
        "#,
    )
    .bind(server_uuid)
    .bind(event)
    .bind(payload)
    .execute(state.database.write())
    .await?;

    Ok(())
}

async fn ensure_not_blacklisted(
    state: &shared::State,
    managed_domain_uuid: uuid::Uuid,
    label: &str,
) -> Result<(), anyhow::Error> {
    let rows = sqlx::query(
        r#"
        SELECT pattern, case_sensitive
        FROM ext_cloudflare_subdomain_blacklist_rules
        WHERE enabled AND (managed_domain_uuid IS NULL OR managed_domain_uuid = $1)
        "#,
    )
    .bind(managed_domain_uuid)
    .fetch_all(state.database.read())
    .await?;

    for row in rows {
        let pattern: String = row.get("pattern");
        let case_sensitive: bool = row.get("case_sensitive");

        let regex = if case_sensitive {
            Regex::new(&pattern)?
        } else {
            Regex::new(&format!("(?i){pattern}"))?
        };

        if regex.is_match(label) {
            return Err(anyhow::anyhow!(
                "subdomain label is not allowed by blacklist policy"
            ));
        }
    }

    Ok(())
}

async fn resolve_target_from_alias(
    state: &shared::State,
    managed_domain_uuid: uuid::Uuid,
    source: Option<&str>,
) -> Result<Option<String>, anyhow::Error> {
    let rows = sqlx::query(
        r#"
        SELECT source, target
        FROM ext_cloudflare_subdomain_alias_rules
        WHERE enabled AND (managed_domain_uuid IS NULL OR managed_domain_uuid = $1)
        "#,
    )
    .bind(managed_domain_uuid)
    .fetch_all(state.database.read())
    .await?;

    let Some(source) = source else {
        return Ok(None);
    };

    for row in rows {
        let rule_source: String = row.get("source");
        if rule_source == source {
            return Ok(Some(row.get("target")));
        }
    }

    Ok(Some(source.to_string()))
}

struct AllocationTarget {
    ip: Option<String>,
    ip_alias: Option<String>,
    port: i32,
}

async fn load_server_allocation_target(
    state: &shared::State,
    server: &Server,
    allocation_uuid: Option<uuid::Uuid>,
) -> Result<Option<AllocationTarget>, anyhow::Error> {
    if let Some(allocation_uuid) = allocation_uuid {
        let row = sqlx::query(
            r#"
            SELECT host(node_allocations.ip) AS ip, node_allocations.ip_alias, node_allocations.port
            FROM server_allocations
            JOIN node_allocations ON node_allocations.uuid = server_allocations.allocation_uuid
            WHERE server_allocations.server_uuid = $1 AND server_allocations.uuid = $2
            "#,
        )
        .bind(server.uuid)
        .bind(allocation_uuid)
        .fetch_optional(state.database.read())
        .await?;

        let row = row.ok_or_else(|| anyhow::anyhow!("selected allocation was not found for this server"))?;
        return Ok(Some(AllocationTarget {
            ip: normalize_source_value(row.get::<Option<String>, _>("ip")),
            ip_alias: normalize_source_value(row.get::<Option<String>, _>("ip_alias")),
            port: row.get("port"),
        }));
    }

    if let Some(primary) = server.allocation.as_ref() {
        return Ok(Some(AllocationTarget {
            ip: normalize_source_value(Some(primary.allocation.ip.ip().to_string())),
            ip_alias: normalize_source_value(primary.allocation.ip_alias.clone().map(|v| v.to_string())),
            port: primary.allocation.port,
        }));
    }

    let row = sqlx::query(
        r#"
        SELECT host(node_allocations.ip) AS ip, node_allocations.ip_alias, node_allocations.port
        FROM server_allocations
        JOIN node_allocations ON node_allocations.uuid = server_allocations.allocation_uuid
        WHERE server_allocations.server_uuid = $1
        ORDER BY server_allocations.created
        LIMIT 1
        "#,
    )
    .bind(server.uuid)
    .fetch_optional(state.database.read())
    .await?;

    Ok(row.map(|row| AllocationTarget {
        ip: normalize_source_value(row.get::<Option<String>, _>("ip")),
        ip_alias: normalize_source_value(row.get::<Option<String>, _>("ip_alias")),
        port: row.get("port"),
    }))
}

async fn resolve_target_source(
    state: &shared::State,
    server: &Server,
    allocation: &Option<AllocationTarget>,
) -> Result<Option<String>, anyhow::Error> {
    let Some(allocation) = allocation.as_ref() else {
        return Ok(None);
    };

    if let Some(ip_alias) = allocation.ip_alias.as_deref() {
        return Ok(Some(ip_alias.to_string()));
    }

    if let Some(ip) = allocation.ip.as_deref() {
        return Ok(Some(ip.to_string()));
    }

    let node = server.node.fetch(&state.database).await?;
    let node_host = node
        .public_url
        .as_ref()
        .and_then(|url| url.host_str())
        .or_else(|| node.url.host_str())
        .map(ToString::to_string)
        .and_then(|host| normalize_source_value(Some(host)));

    Ok(node_host)
}

fn normalize_source_value(value: Option<String>) -> Option<String> {
    let value = value.map(|v| v.trim().to_string()).filter(|v| !v.is_empty());
    let Some(value) = value else {
        return None;
    };

    if std::net::IpAddr::from_str(&value)
        .map(|ip| ip.is_unspecified())
        .unwrap_or(false)
    {
        return None;
    }

    Some(value)
}

fn build_record_name(
    record_type: &str,
    fqdn: &str,
    service: Option<&str>,
    protocol: Option<&str>,
) -> String {
    if record_type != "SRV" {
        return fqdn.to_string();
    }

    let service = normalize_srv_segment(service.unwrap_or("minecraft"));
    let protocol = normalize_srv_segment(protocol.unwrap_or("tcp"));
    format!("{service}.{protocol}.{fqdn}")
}

fn normalize_srv_segment(value: &str) -> String {
    let value = value.trim();
    if value.starts_with('_') {
        value.to_string()
    } else {
        format!("_{value}")
    }
}

fn resolve_assignment_content(row: &sqlx::postgres::PgRow) -> String {
    let record_type: String = row.get("record_type");

    if record_type == "TXT" {
        format!("server={}", row.get::<uuid::Uuid, _>("server_uuid"))
    } else {
        row.get::<Option<String>, _>("resolved_target")
            .or(row.get::<Option<String>, _>("allocation_ip"))
            .unwrap_or_default()
    }
}

async fn upsert_generated_record(
    state: &shared::State,
    assignment_uuid: uuid::Uuid,
    record: &DnsRecordDesired,
    managed: Option<&DnsRecordManaged>,
) -> Result<(), anyhow::Error> {
    sqlx::query(
        r#"
        INSERT INTO ext_cloudflare_subdomain_generated_records (
            assignment_uuid, cloudflare_record_id, record_type, name, content,
            ttl, proxied, priority, port, weight, service, protocol, status
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, 'active')
        ON CONFLICT (assignment_uuid, record_type, name, COALESCE(service, ''), COALESCE(protocol, ''))
        DO UPDATE SET
            cloudflare_record_id = EXCLUDED.cloudflare_record_id,
            content = EXCLUDED.content,
            ttl = EXCLUDED.ttl,
            proxied = EXCLUDED.proxied,
            priority = EXCLUDED.priority,
            port = EXCLUDED.port,
            weight = EXCLUDED.weight,
            service = EXCLUDED.service,
            protocol = EXCLUDED.protocol,
            status = EXCLUDED.status,
            updated = NOW()
        "#,
    )
    .bind(assignment_uuid)
    .bind(
        managed
            .map(|m| m.id.clone())
            .or_else(|| Some(String::new()))
            .filter(|id| !id.is_empty()),
    )
    .bind(&record.record_type)
    .bind(&record.name)
    .bind(&record.content)
    .bind(record.ttl)
    .bind(record.proxied)
    .bind(record.priority)
    .bind(record.port)
    .bind(record.weight)
    .bind(record.service.as_deref())
    .bind(record.protocol.as_deref())
    .execute(state.database.write())
    .await?;

    Ok(())
}

fn record_key(record: &DnsRecordDesired) -> String {
    format!(
        "{}|{}|{}|{}",
        record.record_type,
        record.name,
        record.service.as_deref().unwrap_or_default(),
        record.protocol.as_deref().unwrap_or_default()
    )
}

fn record_key_from_row(row: &sqlx::postgres::PgRow) -> String {
    format!(
        "{}|{}|{}|{}",
        row.get::<String, _>("record_type"),
        row.get::<String, _>("name"),
        row.get::<Option<String>, _>("service").unwrap_or_default(),
        row.get::<Option<String>, _>("protocol").unwrap_or_default()
    )
}

async fn load_provider_for_server(
    state: &shared::State,
    server_uuid: uuid::Uuid,
) -> Result<Option<CloudflareProvider>, anyhow::Error> {
    let row = sqlx::query(
        r#"
        SELECT p.api_token_encrypted
        FROM ext_cloudflare_subdomain_assignments a
        JOIN ext_cloudflare_subdomain_managed_domains d ON d.uuid = a.managed_domain_uuid
        JOIN ext_cloudflare_subdomain_providers p ON p.uuid = d.provider_uuid
        WHERE a.server_uuid = $1
        "#,
    )
    .bind(server_uuid)
    .fetch_optional(state.database.read())
    .await?;

    let Some(row) = row else {
        return Ok(None);
    };

    let encrypted: Vec<u8> = row.get("api_token_encrypted");
    let token = state.database.decrypt(encrypted).await?;

    Ok(Some(CloudflareProvider::new(state.client.clone(), token)))
}

async fn get_assignment(
    state: &shared::State,
    server_uuid: uuid::Uuid,
) -> Result<Option<ApiAssignment>, anyhow::Error> {
    let assignment_row = sqlx::query(
        r#"
        SELECT uuid, server_uuid, managed_domain_uuid, record_type, label, fqdn, status, assignment_source,
               allocation_ip, allocation_ip_alias, allocation_port, resolved_target, updated, created
        FROM ext_cloudflare_subdomain_assignments
        WHERE server_uuid = $1
        "#,
    )
    .bind(server_uuid)
    .fetch_optional(state.database.read())
    .await?;

    let Some(row) = assignment_row else {
        return Ok(None);
    };

    let assignment_uuid: uuid::Uuid = row.get("uuid");

    let records = sqlx::query(
        r#"
        SELECT uuid, cloudflare_record_id, record_type, name, content, ttl, proxied,
               priority, port, weight, service, protocol, status
        FROM ext_cloudflare_subdomain_generated_records
        WHERE assignment_uuid = $1
        ORDER BY created
        "#,
    )
    .bind(assignment_uuid)
    .fetch_all(state.database.read())
    .await?
    .into_iter()
    .map(|record| ApiGeneratedRecord {
        uuid: record.get("uuid"),
        cloudflare_record_id: record.get("cloudflare_record_id"),
        record_type: record.get("record_type"),
        name: record.get("name"),
        content: record.get("content"),
        ttl: record.get("ttl"),
        proxied: record.get("proxied"),
        priority: record.get("priority"),
        port: record.get("port"),
        weight: record.get("weight"),
        service: record.get("service"),
        protocol: record.get("protocol"),
        status: record.get("status"),
    })
    .collect::<Vec<_>>();

    Ok(Some(ApiAssignment {
        uuid: assignment_uuid,
        server_uuid: row.get("server_uuid"),
        managed_domain_uuid: row.get("managed_domain_uuid"),
        record_type: row.get("record_type"),
        label: row.get("label"),
        fqdn: row.get("fqdn"),
        status: row.get("status"),
        assignment_source: row.get("assignment_source"),
        allocation_ip: row.get("allocation_ip"),
        allocation_ip_alias: row.get("allocation_ip_alias"),
        allocation_port: row.get("allocation_port"),
        resolved_target: row.get("resolved_target"),
        records,
        updated: row.get::<chrono::NaiveDateTime, _>("updated").and_utc(),
        created: row.get::<chrono::NaiveDateTime, _>("created").and_utc(),
    }))
}

fn map_managed_domain_row(row: &sqlx::postgres::PgRow) -> Result<ApiManagedDomain, anyhow::Error> {
    Ok(ApiManagedDomain {
        uuid: row.get("uuid"),
        provider_uuid: row.get("provider_uuid"),
        display_name: row.get("display_name"),
        base_domain: row.get("base_domain"),
        zone_name: row.get("zone_name"),
        zone_id: row.get("zone_id"),
        default_ttl: row.get("default_ttl"),
        default_proxied: row.get("default_proxied"),
        game: row.get("game"),
        allow_user_updates: row.get("allow_user_updates"),
        allowed_record_types: row.get("allowed_record_types"),
    })
}

struct TemplateContext {
    label: String,
    fqdn: String,
    base_domain: String,
    ip: Option<String>,
    ip_alias: Option<String>,
    target: Option<String>,
    port: Option<i32>,
    server_uuid: uuid::Uuid,
}

fn render_template(template: &str, context: &TemplateContext) -> String {
    template
        .replace("{{label}}", &context.label)
        .replace("{{fqdn}}", &context.fqdn)
        .replace("{{base_domain}}", &context.base_domain)
        .replace("{{ip}}", context.ip.as_deref().unwrap_or_default())
        .replace(
            "{{ip_alias}}",
            context.ip_alias.as_deref().unwrap_or_default(),
        )
        .replace("{{target}}", context.target.as_deref().unwrap_or_default())
        .replace(
            "{{port}}",
            &context
                .port
                .map(|port| port.to_string())
                .unwrap_or_else(|| "".to_string()),
        )
        .replace("{{server_uuid}}", &context.server_uuid.to_string())
}

fn validate_desired_record(record: &mut DnsRecordDesired) -> Result<(), anyhow::Error> {
    if record.record_type == "SRV" {
        let target = record.content.trim();
        if target.is_empty() {
            return Err(anyhow::anyhow!(
                "SRV record target is empty. use a hostname target (for example mc.example.com)"
            ));
        }

        if std::net::IpAddr::from_str(target).is_ok() {
            return Err(anyhow::anyhow!(
                "SRV target must be a hostname, not an IP address. update alias/template target to a hostname"
            ));
        }
    }

    Ok(())
}
