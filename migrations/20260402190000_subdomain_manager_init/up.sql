CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_providers (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name varchar(255) NOT NULL UNIQUE,
    provider_type varchar(32) NOT NULL DEFAULT 'cloudflare',
    api_token_encrypted bytea NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created timestamp NOT NULL DEFAULT NOW(),
    updated timestamp NOT NULL DEFAULT NOW(),
    CHECK (provider_type IN ('cloudflare'))
);

CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_managed_domains (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider_uuid uuid NOT NULL REFERENCES ext_cloudflare_subdomain_providers(uuid) ON DELETE CASCADE,
    display_name varchar(255) NOT NULL,
    base_domain varchar(255) NOT NULL UNIQUE,
    zone_name varchar(255) NOT NULL,
    zone_id varchar(64) NOT NULL,
    default_ttl integer NOT NULL DEFAULT 300,
    default_proxied boolean NOT NULL DEFAULT false,
    game varchar(64),
    allow_user_updates boolean NOT NULL DEFAULT true,
    allowed_record_types text[] NOT NULL DEFAULT ARRAY['A', 'AAAA', 'CNAME', 'SRV', 'TXT']::text[],
    enabled boolean NOT NULL DEFAULT true,
    created timestamp NOT NULL DEFAULT NOW(),
    updated timestamp NOT NULL DEFAULT NOW(),
    CHECK (default_ttl >= 1 AND default_ttl <= 86400)
);

CREATE INDEX IF NOT EXISTS ext_cloudflare_subdomain_managed_domains_provider_idx
    ON ext_cloudflare_subdomain_managed_domains(provider_uuid);

CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_blacklist_rules (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    managed_domain_uuid uuid REFERENCES ext_cloudflare_subdomain_managed_domains(uuid) ON DELETE CASCADE,
    pattern text NOT NULL,
    case_sensitive boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    description text,
    created timestamp NOT NULL DEFAULT NOW(),
    updated timestamp NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ext_cloudflare_subdomain_blacklist_rules_unique_idx
    ON ext_cloudflare_subdomain_blacklist_rules(managed_domain_uuid, pattern);

CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_alias_rules (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    managed_domain_uuid uuid REFERENCES ext_cloudflare_subdomain_managed_domains(uuid) ON DELETE CASCADE,
    source varchar(255) NOT NULL,
    target varchar(255) NOT NULL,
    enabled boolean NOT NULL DEFAULT true,
    created timestamp NOT NULL DEFAULT NOW(),
    updated timestamp NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS ext_cloudflare_subdomain_alias_rules_unique_idx
    ON ext_cloudflare_subdomain_alias_rules(managed_domain_uuid, source);

CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_record_templates (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    managed_domain_uuid uuid NOT NULL REFERENCES ext_cloudflare_subdomain_managed_domains(uuid) ON DELETE CASCADE,
    egg_uuid uuid REFERENCES nest_eggs(uuid) ON DELETE SET NULL,
    game varchar(64),
    record_type varchar(16) NOT NULL,
    content_template text NOT NULL,
    ttl integer,
    proxied boolean,
    priority integer,
    weight integer,
    port integer,
    service varchar(64),
    protocol varchar(16),
    only_non_default_port boolean NOT NULL DEFAULT false,
    enabled boolean NOT NULL DEFAULT true,
    created timestamp NOT NULL DEFAULT NOW(),
    updated timestamp NOT NULL DEFAULT NOW(),
    CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'SRV', 'TXT'))
);

CREATE INDEX IF NOT EXISTS ext_cloudflare_subdomain_record_templates_domain_idx
    ON ext_cloudflare_subdomain_record_templates(managed_domain_uuid);

CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_assignments (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_uuid uuid NOT NULL UNIQUE REFERENCES servers(uuid) ON DELETE CASCADE,
    managed_domain_uuid uuid NOT NULL REFERENCES ext_cloudflare_subdomain_managed_domains(uuid) ON DELETE RESTRICT,
    record_type varchar(16) NOT NULL,
    label varchar(63) NOT NULL,
    fqdn varchar(255) NOT NULL UNIQUE,
    status varchar(32) NOT NULL DEFAULT 'assigned',
    assignment_source varchar(32) NOT NULL DEFAULT 'user',
    allocation_ip varchar(64),
    allocation_ip_alias varchar(255),
    allocation_port integer,
    resolved_target varchar(255),
    created timestamp NOT NULL DEFAULT NOW(),
    updated timestamp NOT NULL DEFAULT NOW(),
    CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'SRV', 'TXT')),
    CHECK (status IN ('assigned', 'unknown', 'pending_reassignment', 'unassigned')),
    CHECK (assignment_source IN ('user', 'admin', 'system'))
);

CREATE INDEX IF NOT EXISTS ext_cloudflare_subdomain_assignments_domain_idx
    ON ext_cloudflare_subdomain_assignments(managed_domain_uuid);

CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_generated_records (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    assignment_uuid uuid NOT NULL REFERENCES ext_cloudflare_subdomain_assignments(uuid) ON DELETE CASCADE,
    cloudflare_record_id varchar(128),
    record_type varchar(16) NOT NULL,
    name varchar(255) NOT NULL,
    content text NOT NULL,
    ttl integer NOT NULL,
    proxied boolean,
    priority integer,
    port integer,
    weight integer,
    service varchar(64),
    protocol varchar(16),
    status varchar(32) NOT NULL DEFAULT 'active',
    created timestamp NOT NULL DEFAULT NOW(),
    updated timestamp NOT NULL DEFAULT NOW(),
    CHECK (status IN ('active', 'unknown', 'pending_delete')),
    CHECK (record_type IN ('A', 'AAAA', 'CNAME', 'SRV', 'TXT'))
);

CREATE UNIQUE INDEX IF NOT EXISTS ext_cloudflare_subdomain_generated_records_logical_idx
    ON ext_cloudflare_subdomain_generated_records(
        assignment_uuid,
        record_type,
        name,
        COALESCE(service, ''),
        COALESCE(protocol, '')
    );

CREATE INDEX IF NOT EXISTS ext_cloudflare_subdomain_generated_records_assignment_idx
    ON ext_cloudflare_subdomain_generated_records(assignment_uuid);

CREATE TABLE IF NOT EXISTS ext_cloudflare_subdomain_audit_events (
    uuid uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    server_uuid uuid NOT NULL REFERENCES servers(uuid) ON DELETE CASCADE,
    event varchar(128) NOT NULL,
    payload jsonb NOT NULL,
    created timestamp NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS ext_cloudflare_subdomain_audit_events_server_idx
    ON ext_cloudflare_subdomain_audit_events(server_uuid, created DESC);
