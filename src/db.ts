import { Client } from 'pg'
import { Schema, TableInfo, PolicyInfo, GrantInfo, OwnerColumn } from './types'

// Column names that mark a table as "user-owned" in a typical multi-tenant app.
// Extend this list for your own conventions.
export const OWNERSHIP_COLUMNS = [
  'user_id',
  'owner_id',
  'profile_id',
  'account_id',
  'uid',
  'created_by',
  'owner',
]

const Q_TABLES = `
  select c.relname as table, c.relrowsecurity as rls_enabled, c.relforcerowsecurity as rls_forced
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = $1 and c.relkind = 'r'
  order by c.relname
`

const Q_POLICIES = `
  select
    c.relname as table,
    pol.polname as name,
    case pol.polcmd
      when 'r' then 'SELECT' when 'a' then 'INSERT'
      when 'w' then 'UPDATE' when 'd' then 'DELETE'
      when '*' then 'ALL' end as cmd,
    pg_get_expr(pol.polqual, pol.polrelid) as using_expr,
    pg_get_expr(pol.polwithcheck, pol.polrelid) as check_expr,
    coalesce(
      (select array_agg(r.rolname order by r.rolname)
         from pg_roles r where r.oid = any(pol.polroles) and r.rolname <> 'public'),
      '{}'
    ) as roles
  from pg_policy pol
  join pg_class c on c.oid = pol.polrelid
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = $1
  order by c.relname, cmd
`

const Q_GRANTS = `
  select table_name as table, grantee, privilege_type as privilege
  from information_schema.role_table_grants
  where table_schema = $1 and grantee in ('anon', 'authenticated')
`

const Q_OWNER_COLS = `
  select c.relname as table, a.attname as column, (not a.attnotnull) as nullable
  from pg_attribute a
  join pg_class c on c.oid = a.attrelid
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = $1 and c.relkind = 'r'
    and a.attnum > 0 and not a.attisdropped
    and a.attname = any($2::text[])
`

export async function introspect(
  connectionString: string,
  schema: string
): Promise<Schema> {
  const client = new Client({
    connectionString,
    // Supabase (and most managed Postgres) require TLS. We don't pin the CA
    // here because connection strings vary; the traffic is still encrypted.
    ssl: { rejectUnauthorized: false },
    // Fail fast instead of hanging on an unreachable host.
    connectionTimeoutMillis: 15_000,
    statement_timeout: 20_000,
  })

  await client.connect()
  try {
    const [tables, policies, grants, ownerCols] = await Promise.all([
      client.query(Q_TABLES, [schema]),
      client.query(Q_POLICIES, [schema]),
      client.query(Q_GRANTS, [schema]),
      client.query(Q_OWNER_COLS, [schema, OWNERSHIP_COLUMNS]),
    ])

    return {
      // Map explicitly: the query returns snake_case columns. Casting the raw rows
      // left rlsEnabled undefined, so every table was reported as RLS-disabled.
      tables: tables.rows.map(
        (r): TableInfo => ({
          table: r.table,
          rlsEnabled: r.rls_enabled === true,
          rlsForced: r.rls_forced === true,
        })
      ),
      policies: policies.rows.map(
        (r): PolicyInfo => ({
          table: r.table,
          name: r.name,
          cmd: r.cmd,
          usingExpr: r.using_expr,
          checkExpr: r.check_expr,
          roles: r.roles ?? [],
        })
      ),
      grants: grants.rows as GrantInfo[],
      ownerColumns: ownerCols.rows as OwnerColumn[],
    }
  } finally {
    await client.end()
  }
}
