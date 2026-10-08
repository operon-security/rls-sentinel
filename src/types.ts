export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFO'

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']

export interface Finding {
  /** Stable check id, e.g. "RLS_DISABLED". */
  check: string
  severity: Severity
  /** Table the finding is about, or null for schema-wide findings. */
  table: string | null
  title: string
  detail: string
  remediation: string
}

export interface TableInfo {
  table: string
  rlsEnabled: boolean
  rlsForced: boolean
}

export interface PolicyInfo {
  table: string
  name: string
  /** SELECT | INSERT | UPDATE | DELETE | ALL */
  cmd: string
  usingExpr: string | null
  checkExpr: string | null
  /** role names the policy applies to; empty array means PUBLIC (all roles). */
  roles: string[]
}

export interface GrantInfo {
  table: string
  grantee: string
  privilege: string
}

export interface OwnerColumn {
  table: string
  column: string
  nullable: boolean
}

export interface Schema {
  tables: TableInfo[]
  policies: PolicyInfo[]
  grants: GrantInfo[]
  ownerColumns: OwnerColumn[]
}
