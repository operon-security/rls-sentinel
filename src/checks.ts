import { Schema, Finding, PolicyInfo } from './types'

// --- expression heuristics -------------------------------------------------

/** A policy expression that lets every row through. */
function isUnrestricted(expr: string | null): boolean {
  if (expr === null) return false
  const e = expr.trim().toLowerCase()
  return e === 'true' || e === '(true)'
}

/** Does the expression tie a row to the caller (auth.uid() compared to a column)? */
function hasOwnershipCheck(expr: string | null): boolean {
  if (!expr) return false
  const e = expr.toLowerCase()
  // auth.uid() = <col>  OR  <col> = auth.uid()  OR a subquery/membership on auth.uid()
  if (/auth\.uid\(\)\s*=\s*[a-z_][\w.]*/.test(e)) return true
  if (/[a-z_][\w.]*\s*=\s*auth\.uid\(\)/.test(e)) return true
  if (/auth\.uid\(\)/.test(e) && /\b(in|exists|any)\b/.test(e)) return true
  return false
}

/** Only checks "is the caller logged in", not "does the caller own this row". */
function isLoggedInOnly(expr: string | null): boolean {
  if (!expr) return false
  const e = expr.toLowerCase()
  const loggedIn =
    /auth\.role\(\)\s*=\s*'authenticated'/.test(e) ||
    /auth\.uid\(\)\s+is\s+not\s+null/.test(e) ||
    /\(\s*auth\.jwt\(\)/.test(e)
  return loggedIn && !hasOwnershipCheck(e)
}

const WRITE = new Set(['INSERT', 'UPDATE', 'DELETE'])

// --- the audit -------------------------------------------------------------

export function audit(schema: string, s: Schema): Finding[] {
  const findings: Finding[] = []

  const policiesByTable = new Map<string, PolicyInfo[]>()
  for (const p of s.policies) {
    const arr = policiesByTable.get(p.table) ?? []
    arr.push(p)
    policiesByTable.set(p.table, arr)
  }

  const grantsByTable = new Map<string, { grantee: string; privilege: string }[]>()
  for (const g of s.grants) {
    const arr = grantsByTable.get(g.table) ?? []
    arr.push({ grantee: g.grantee, privilege: g.privilege })
    grantsByTable.set(g.table, arr)
  }

  const ownerColsByTable = new Map<string, { column: string; nullable: boolean }[]>()
  for (const c of s.ownerColumns) {
    const arr = ownerColsByTable.get(c.table) ?? []
    arr.push({ column: c.column, nullable: c.nullable })
    ownerColsByTable.set(c.table, arr)
  }

  for (const t of s.tables) {
    const table = t.table
    const pols = policiesByTable.get(table) ?? []
    const grants = grantsByTable.get(table) ?? []
    const ownerCols = ownerColsByTable.get(table) ?? []
    const owned = ownerCols.length > 0
    const grantees = new Set(grants.map((g) => g.grantee))
    const anonWrite = grants.some(
      (g) => g.grantee === 'anon' && WRITE.has(g.privilege)
    )
    const anonRead = grants.some((g) => g.grantee === 'anon' && g.privilege === 'SELECT')
    const exposedToClient = grantees.has('anon') || grantees.has('authenticated')

    // 1. RLS disabled on a client-reachable table → everyone with the API key
    //    reads/writes every row. The single most severe misconfiguration.
    if (!t.rlsEnabled && exposedToClient) {
      findings.push({
        check: 'RLS_DISABLED',
        severity: anonRead || anonWrite ? 'CRITICAL' : 'HIGH',
        table,
        title: 'Row Level Security is disabled',
        detail:
          `Table "${table}" is reachable by the ${[...grantees].join('/')} role(s) ` +
          `but RLS is OFF. Every row is readable${anonWrite ? ' and writable' : ''} by ` +
          `anyone holding the ${anonRead ? 'public anon' : 'anon/authenticated'} API key.` +
          (owned ? ' This table looks user-owned (' + ownerCols.map((c) => c.column).join(', ') + '), so this is a cross-tenant data leak.' : ''),
        remediation: `alter table "${schema}"."${table}" enable row level security;  -- then add per-operation policies`,
      })
      continue // further policy checks are moot while RLS is off
    }

    // 2. RLS enabled but NO policies: default-deny. Not a leak, but a functional
    //    bug — every query returns empty. Easy to ship by accident.
    if (t.rlsEnabled && pols.length === 0 && exposedToClient) {
      findings.push({
        check: 'RLS_NO_POLICY',
        severity: 'MEDIUM',
        table,
        title: 'RLS enabled with no policies',
        detail:
          `Table "${table}" has RLS on but zero policies, so every client query ` +
          `returns no rows. Usually an unfinished migration — verify this is intentional.`,
        remediation: `Add SELECT/INSERT/UPDATE/DELETE policies, or disable RLS if the table is genuinely not client-facing.`,
      })
    }

    // per-policy checks
    for (const p of pols) {
      const appliesToClient =
        p.roles.length === 0 || p.roles.includes('anon') || p.roles.includes('authenticated')
      if (!appliesToClient) continue

      // 3. Read/ALL policy that lets every row through (USING true).
      if ((p.cmd === 'SELECT' || p.cmd === 'ALL') && isUnrestricted(p.usingExpr)) {
        findings.push({
          check: 'POLICY_UNRESTRICTED',
          severity: 'CRITICAL',
          table,
          title: 'Policy exposes all rows (USING true)',
          detail:
            `Policy "${p.name}" on "${table}" (${p.cmd}) uses USING (true) for the ` +
            `${p.roles.length ? p.roles.join('/') : 'public'} role, so any client reads every row in the table.`,
          remediation: `Replace with an ownership check, e.g. using (auth.uid() = user_id).`,
        })
      }

      // 4. Policy that only checks "logged in", not ownership → any authenticated
      //    user can read/modify everyone's rows.
      if (
        (p.cmd === 'SELECT' || p.cmd === 'UPDATE' || p.cmd === 'DELETE' || p.cmd === 'ALL') &&
        isLoggedInOnly(p.usingExpr)
      ) {
        findings.push({
          check: 'POLICY_LOGGED_IN_ONLY',
          severity: 'HIGH',
          table,
          title: 'Policy checks authentication, not ownership',
          detail:
            `Policy "${p.name}" on "${table}" (${p.cmd}) only requires the caller to be ` +
            `logged in (no auth.uid() = owner check). Any authenticated user can reach every other user's rows.`,
          remediation: `Add an ownership predicate, e.g. using (auth.uid() = user_id).`,
        })
      }

      // 5. INSERT (or ALL) without WITH CHECK → a user can insert rows they don't own.
      if ((p.cmd === 'INSERT' || p.cmd === 'ALL') && p.checkExpr === null) {
        findings.push({
          check: 'INSERT_NO_WITH_CHECK',
          severity: p.cmd === 'INSERT' ? 'HIGH' : 'MEDIUM',
          table,
          title: 'Insert policy has no WITH CHECK',
          detail:
            `Policy "${p.name}" on "${table}" (${p.cmd}) has no WITH CHECK, so an inserted ` +
            `row's ownership column is not validated — a user can create rows assigned to another user.`,
          remediation: `Add with check (auth.uid() = user_id) to the policy.`,
        })
      }

      // 6. WITH CHECK that lets anything through.
      if (WRITE.has(p.cmd) && isUnrestricted(p.checkExpr)) {
        findings.push({
          check: 'WITH_CHECK_UNRESTRICTED',
          severity: 'HIGH',
          table,
          title: 'Write policy WITH CHECK is unrestricted',
          detail: `Policy "${p.name}" on "${table}" (${p.cmd}) uses WITH CHECK (true) — writes are not constrained to the owner.`,
          remediation: `Constrain WITH CHECK to the owner, e.g. with check (auth.uid() = user_id).`,
        })
      }
    }

    // 7. Owned table with a NULLABLE ownership column. A NULL owner matches no
    //    auth.uid() = user_id policy: such rows silently become invisible and
    //    un-deletable to everyone, and an insert that forgets to set the owner
    //    (e.g. via the service role) produces an orphaned, unprotected row.
    for (const c of ownerCols) {
      if (c.nullable) {
        findings.push({
          check: 'NULLABLE_OWNER',
          severity: 'MEDIUM',
          table,
          title: `Ownership column "${c.column}" is nullable`,
          detail:
            `On "${table}", "${c.column}" allows NULL. A row with a NULL owner matches no ` +
            `"auth.uid() = ${c.column}" policy, so it is invisible and un-deletable through the API, ` +
            `and a service-role insert that omits the owner creates an unprotected orphan row.`,
          remediation: `alter table "${schema}"."${table}" alter column "${c.column}" set not null;  -- after backfilling any NULLs`,
        })
      }
    }

    // 8. Owned + RLS on, but a command has no policy (and no ALL policy).
    if (owned && t.rlsEnabled && pols.length > 0) {
      const hasAll = pols.some((p) => p.cmd === 'ALL')
      if (!hasAll) {
        const covered = new Set(pols.map((p) => p.cmd))
        for (const cmd of ['SELECT', 'INSERT', 'UPDATE', 'DELETE']) {
          if (!covered.has(cmd)) {
            findings.push({
              check: 'MISSING_POLICY',
              severity: 'LOW',
              table,
              title: `No ${cmd} policy`,
              detail:
                `User-owned table "${table}" has RLS on but no ${cmd} policy, so ${cmd} is ` +
                `denied to all clients. Intentional? If this table should support ${cmd}, add the policy.`,
              remediation: `create policy "${table.toLowerCase()}_${cmd.toLowerCase()}_own" on "${schema}"."${table}" for ${cmd.toLowerCase()} ${cmd === 'INSERT' ? 'with check' : 'using'} (auth.uid() = user_id);`,
            })
          }
        }
      }
    }

    // 9. RLS enabled but not FORCED — the table owner / service role bypasses RLS.
    //    Expected, but a reminder: server code using the service-role key MUST
    //    filter by a verified user id (getUser(), never getSession()).
    if (t.rlsEnabled && !t.rlsForced && owned) {
      findings.push({
        check: 'RLS_NOT_FORCED',
        severity: 'INFO',
        table,
        title: 'RLS is not forced (service role bypasses it)',
        detail:
          `On "${table}", RLS is enabled but not FORCED, so the service-role key bypasses it ` +
          `(by design). Any server code using that key must scope queries to a verified user id.`,
        remediation: `Resolve identity server-side with getUser()/getClaims(), never the unverified getSession(); optionally: alter table "${schema}"."${table}" force row level security;`,
      })
    }
  }

  return findings
}
