export interface ApiProvider {
  uuid: string;
  name: string;
  providerType: string;
  enabled: boolean;
  created: string;
  updated: string;
}

export interface ApiManagedDomain {
  uuid: string;
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
}

export interface ApiBlacklistRule {
  uuid: string;
  managedDomainUuid: string | null;
  pattern: string;
  caseSensitive: boolean;
  enabled: boolean;
  description: string | null;
}

export interface ApiAliasRule {
  uuid: string;
  managedDomainUuid: string | null;
  source: string;
  target: string;
  enabled: boolean;
}

export interface ApiRecordTemplate {
  uuid: string;
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
}

export interface ApiGeneratedRecord {
  uuid: string;
  cloudflareRecordId: string | null;
  recordType: string;
  name: string;
  content: string;
  ttl: number;
  proxied: boolean | null;
  priority: number | null;
  port: number | null;
  weight: number | null;
  service: string | null;
  protocol: string | null;
  status: string;
}

export interface ApiAssignment {
  uuid: string;
  serverUuid: string;
  managedDomainUuid: string;
  recordType: string;
  label: string;
  fqdn: string;
  status: string;
  assignmentSource: string;
  allocationIp: string | null;
  allocationIpAlias: string | null;
  allocationPort: number | null;
  resolvedTarget: string | null;
  records: ApiGeneratedRecord[];
  created: string;
  updated: string;
}

export interface AdminConfigResponse {
  providers: ApiProvider[];
  managedDomains: ApiManagedDomain[];
  blacklistRules: ApiBlacklistRule[];
  aliasRules: ApiAliasRule[];
  recordTemplates: ApiRecordTemplate[];
}

export interface ClientSubdomainResponse {
  assignment: ApiAssignment | null;
  managedDomains: ApiManagedDomain[];
}
