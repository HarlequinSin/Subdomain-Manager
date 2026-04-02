import { axiosInstance } from '@/api/axios.ts';
import type { AdminConfigResponse, ApiAssignment, ClientSubdomainResponse } from '../types/index.ts';

export async function getAdminConfig(): Promise<AdminConfigResponse> {
  const { data } = await axiosInstance.get('/api/admin/subdomain-manager/config');
  return data.config;
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
