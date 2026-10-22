import { Client } from 'pg'
import { Schema, TableInfo, PolicyInfo, GrantInfo, OwnerColumn, ViewInfo, DefinerFunction } from './types'

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
      -- rolname is type "name"; node-pg does not parse name[] into a JS array, so
      -- cast to text[] or roles arrives as the string "{anon,authenticated}".
      (select array_agg(r.rolname::text order by r.rolname)
         from pg_roles r where r.oid = any(pol.polroles) and r.rolname <> 'public'),
      '{}'::text[]
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

// Views run with their OWNER's rights unless created with security_invoker=true
// (Postgres 15+), so a view over an RLS-protected table can hand every row to the
// API. Materialized views cannot be security_invoker at all.
const Q_VIEWS = `
  select c.relname as view, c.relkind as kind,
    coalesce(c.reloptions::text[] && array['security_invoker=true','security_invoker=on','security_invoker=1'], false) as invoker,
    has_table_privilege('anon', c.oid, 'SELECT') as anon_select,
    has_table_privilege('authenticated', c.oid, 'SELECT') as auth_select
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
  where n.nspname = $1 and c.relkind in ('v', 'm')
  order by c.relname
`

// SECURITY DEFINER functions run as their owner (usually postgres, which bypasses
// RLS) and are callable through /rest/v1/rpc. Trigger functions and extension
// members are skipped: they are not callable that way.
const Q_DEFINER_FUNCS = `
  select p.proname as name, pg_get_function_identity_arguments(p.oid) as args,
    has_function_privilege('anon', p.oid, 'EXECUTE') as anon_exec,
    has_function_privilege('authenticated', p.oid, 'EXECUTE') as auth_exec,
    coalesce(exists(select 1 from unnest(p.proconfig) cfg where cfg like 'search_path=%'), false) as pinned_search_path,
    (p.prosrc ilike '%auth.uid()%') as uses_uid
  from pg_proc p
  join pg_namespace n on n.oid = p.pronamespace
  where n.nspname = $1 and p.prokind = 'f' and p.prosecdef
    and p.prorettype <> 'trigger'::regtype
    and not exists (select 1 from pg_depend dep where dep.objid = p.oid and dep.deptype = 'e')
  order by p.proname
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
    // Defence in depth: every query below only reads system catalogs, but the
    // session is also made read-only at the database level, so a future change
    // that tries to write is rejected by Postgres instead of trusted to code review.
    await client.query('SET SESSION CHARACTERISTICS AS TRANSACTION READ ONLY')
    // One client runs one query at a time; issue them in order.
    const tables = await client.query(Q_TABLES, [schema])
    const policies = await client.query(Q_POLICIES, [schema])
    const grants = await client.query(Q_GRANTS, [schema])
    const ownerCols = await client.query(Q_OWNER_COLS, [schema, OWNERSHIP_COLUMNS])
    const views = await client.query(Q_VIEWS, [schema])
    const funcs = await client.query(Q_DEFINER_FUNCS, [schema])

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
      views: views.rows.map(
        (r): ViewInfo => ({
          view: r.view,
          kind: r.kind === 'm' ? 'm' : 'v',
          invoker: r.invoker === true,
          anonSelect: r.anon_select === true,
          authSelect: r.auth_select === true,
        })
      ),
      definerFunctions: funcs.rows.map(
        (r): DefinerFunction => ({
          name: r.name,
          args: r.args ?? '',
          anonExec: r.anon_exec === true,
          authExec: r.auth_exec === true,
          pinnedSearchPath: r.pinned_search_path === true,
          usesUid: r.uses_uid === true,
        })
      ),
    }
  } finally {
    await client.end()
  }
}
