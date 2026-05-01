import { axiosInstance } from '@/api/axios.ts';
import type { AdminConfigResponse, ApiAssignment, ClientSubdomainResponse } from '../types/index.ts';

const toArray = <T>(value: unknown): T[] => (Array.isArray(value) ? (value as T[]) : []);

function normalizeAdminConfig(payload: unknown): AdminConfigResponse {
  const source = (payload ?? {}) as Record<string, unknown>;

  return {
    providers: toArray<Record<string, unknown>>(source.providers).map((provider) => ({
      uuid: String(provider.uuid ?? ''),
      name: String(provider.name ?? ''),
      providerType: String(provider.providerType ?? provider.provider_type ?? ''),
      enabled: Boolean(provider.enabled),
      created: String(provider.created ?? ''),
      updated: String(provider.updated ?? ''),
    })),
    managedDomains: toArray<Record<string, unknown>>(source.managedDomains ?? source.managed_domains).map((domain) => ({
      uuid: String(domain.uuid ?? ''),
      providerUuid: String(domain.providerUuid ?? domain.provider_uuid ?? ''),
      displayName: String(domain.displayName ?? domain.display_name ?? ''),
      baseDomain: String(domain.baseDomain ?? domain.base_domain ?? ''),
      zoneName: String(domain.zoneName ?? domain.zone_name ?? ''),
      zoneId: String(domain.zoneId ?? domain.zone_id ?? ''),
      defaultTtl: Number(domain.defaultTtl ?? domain.default_ttl ?? 300),
      defaultProxied: Boolean(domain.defaultProxied ?? domain.default_proxied),
      game: (domain.game as string | null | undefined) ?? null,
      allowUserUpdates: Boolean(domain.allowUserUpdates ?? domain.allow_user_updates),
      allowedRecordTypes: toArray<string>(domain.allowedRecordTypes ?? domain.allowed_record_types).map(String),
    })),
    blacklistRules: toArray<Record<string, unknown>>(source.blacklistRules ?? source.blacklist_rules).map((rule) => ({
      uuid: String(rule.uuid ?? ''),
      managedDomainUuid: (rule.managedDomainUuid ?? rule.managed_domain_uuid ?? null) as string | null,
      pattern: String(rule.pattern ?? ''),
      caseSensitive: Boolean(rule.caseSensitive ?? rule.case_sensitive),
      enabled: Boolean(rule.enabled),
      description: (rule.description ?? null) as string | null,
    })),
    aliasRules: toArray<Record<string, unknown>>(source.aliasRules ?? source.alias_rules).map((rule) => ({
      uuid: String(rule.uuid ?? ''),
      managedDomainUuid: (rule.managedDomainUuid ?? rule.managed_domain_uuid ?? null) as string | null,
      source: String(rule.source ?? ''),
      target: String(rule.target ?? ''),
      enabled: Boolean(rule.enabled),
    })),
    recordTemplates: toArray<Record<string, unknown>>(source.recordTemplates ?? source.record_templates).map((template) => ({
      uuid: String(template.uuid ?? ''),
      managedDomainUuid: String(template.managedDomainUuid ?? template.managed_domain_uuid ?? ''),
      eggUuid: (template.eggUuid ?? template.egg_uuid ?? null) as string | null,
      game: (template.game as string | null | undefined) ?? null,
      recordType: String(template.recordType ?? template.record_type ?? ''),
      contentTemplate: String(template.contentTemplate ?? template.content_template ?? ''),
      ttl: (template.ttl ?? null) as number | null,
      proxied: (template.proxied ?? null) as boolean | null,
      priority: (template.priority ?? null) as number | null,
      weight: (template.weight ?? null) as number | null,
      port: (template.port ?? null) as number | null,
      service: (template.service ?? null) as string | null,
      protocol: (template.protocol ?? null) as string | null,
      onlyNonDefaultPort: Boolean(template.onlyNonDefaultPort ?? template.only_non_default_port),
      enabled: Boolean(template.enabled),
    })),
  };
}

export async function getAdminConfig(): Promise<AdminConfigResponse> {
  const { data } = await axiosInstance.get('/api/admin/subdomain-manager/config');
  return normalizeAdminConfig(data.config);
}

export async function upsertProvider(payload: {
  name: string;
  apiToken: string;
  enabled: boolean;
}) {
  const { data } = await axiosInstance.put('/api/admin/subdomain-manager/providers', payload);
  return data.provider;
}

export async function upsertManagedDomain(payload: {
  providerUuid: string;
  displayName: string;
  baseDomain: string;
  zoneName: string;
  zoneId: string;
  defaultTtl: number;
  defaultProxied: boolean;
  game: string | null;
  allowUserUpdates: boolean;
  allowedRecordTypes: string[];
}) {
  const { data } = await axiosInstance.put('/api/admin/subdomain-manager/domains', payload);
  return data.managedDomain;
}

export async function upsertBlacklistRule(payload: {
  managedDomainUuid: string | null;
  pattern: string;
  caseSensitive: boolean;
  enabled: boolean;
  description: string | null;
}) {
  const { data } = await axiosInstance.put('/api/admin/subdomain-manager/blacklist-rules', payload);
  return data.blacklistRule;
}

export async function upsertAliasRule(payload: {
  managedDomainUuid: string | null;
  source: string;
  target: string;
  enabled: boolean;
}) {
  const { data } = await axiosInstance.put('/api/admin/subdomain-manager/alias-rules', payload);
  return data.aliasRule;
}

export async function upsertRecordTemplate(payload: {
  managedDomainUuid: string;
  eggUuid: string | null;
  game: string | null;
  recordType: string;
  contentTemplate: string;
  ttl: number | null;
  proxied: boolean | null;
  priority: number | null;
  weight: number | null;
  port: number | null;
  service: string | null;
  protocol: string | null;
  onlyNonDefaultPort: boolean;
  enabled: boolean;
}) {
  const { data } = await axiosInstance.put('/api/admin/subdomain-manager/record-templates', payload);
  return data.recordTemplate;
}

export async function reconcileServer(serverUuid: string, dryRun: boolean): Promise<ApiAssignment | null> {
  const { data } = await axiosInstance.post('/api/admin/subdomain-manager/reconcile', {
    serverUuid,
    dryRun,
  });

  return data.reconcile.assignment;
}

export async function getServerSubdomain(serverUuid: string): Promise<ClientSubdomainResponse> {
  const { data } = await axiosInstance.get(`/api/client/servers/${serverUuid}/subdomain-manager`);
  return data.subdomain;
}

export async function getServerAllocations(serverUuid: string): Promise<
  Array<{
    uuid: string;
    ip: string;
    ipAlias: string | null;
    port: number;
    isPrimary: boolean;
  }>
> {
  const { data } = await axiosInstance.get(`/api/client/servers/${serverUuid}/allocations`, {
    params: {
      page: 1,
      per_page: 100,
    },
  });

  return data.allocations.data;
}

export async function putServerSubdomain(payload: {
  serverUuid: string;
  managedDomainUuid: string;
  allocationUuid: string | null;
  serverType: 'minecraft' | 'web';
  label: string;
  recordType: string;
  dryRun: boolean;
}): Promise<ApiAssignment> {
  const { data } = await axiosInstance.put(`/api/client/servers/${payload.serverUuid}/subdomain-manager`, {
    managedDomainUuid: payload.managedDomainUuid,
    allocationUuid: payload.allocationUuid,
    serverType: payload.serverType,
    label: payload.label,
    recordType: payload.recordType,
    dryRun: payload.dryRun,
  });

  return data.assignment;
}

export async function deleteServerSubdomain(serverUuid: string): Promise<void> {
  await axiosInstance.delete(`/api/client/servers/${serverUuid}/subdomain-manager`);
}
