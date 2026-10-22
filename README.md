# RLS Sentinel

[![fixture](https://github.com/operon-security/rls-sentinel/actions/workflows/fixture.yml/badge.svg)](https://github.com/operon-security/rls-sentinel/actions/workflows/fixture.yml)

**Find the data leak in your Supabase app before your users — or an attacker — do.**

Supabase hands you a Postgres database with an API key that ships straight to
the browser. The *only* thing standing between one customer and every other
customer's data is Row Level Security — and RLS is quietly easy to get wrong:
a table with RLS left off, a policy that checks "is logged in" instead of "owns
this row", an insert with no `WITH CHECK`, a nullable owner column. Each one is
an invisible, silent cross-tenant leak. None of them throw an error.

RLS Sentinel connects to your database, reads the actual policies and grants,
and reports exactly where a multi-tenant app leaks — with the fix for each.

```
  RLS Sentinel — Supabase / Postgres security audit
  target: postgresql://postgres:****@db.xxxx.supabase.co:5432/postgres

   CRITICAL  profiles — Row Level Security is disabled
      Table "profiles" is reachable by the anon/authenticated role(s) but RLS is OFF...
      fix: alter table "public"."profiles" enable row level security;

   HIGH  invoices — Policy checks authentication, not ownership
      Policy "invoices_read" only requires the caller to be logged in...
      fix: Add an ownership predicate, e.g. using (auth.uid() = user_id).

  Summary:  1 crit   1 high   2 med   0 low   1 info
  Security score: 33/100
```

## Quick start (60 seconds)

```bash
git clone https://github.com/operon-security/rls-sentinel
cd rls-sentinel && npm install && npm run build
node dist/index.js --url "postgresql://postgres:PASSWORD@db.YOURPROJECT.supabase.co:5432/postgres"
```

## What it checks

| Check | Severity | What it catches |
|---|---|---|
| RLS disabled | CRITICAL/HIGH | Client-reachable table with RLS off — every row readable with the public key |
| Policy `USING (true)` | CRITICAL | A policy that returns every row to any client |
| Logged-in-only policy | HIGH | Checks `auth.role()`/`auth.uid() IS NOT NULL` but not ownership — any user reads everyone's rows |
| INSERT without `WITH CHECK` | HIGH | Users can insert rows owned by someone else |
| Unrestricted `WITH CHECK` | HIGH | Writes not constrained to the owner |
| Nullable owner column | MEDIUM | NULL-owner rows match no policy: invisible, un-deletable, orphaned |
| RLS on, no policies | MEDIUM | Default-deny — every query silently returns empty |
| Missing per-command policy | LOW | Owned table with no SELECT/INSERT/UPDATE/DELETE policy |
| RLS not forced | INFO | Service role bypasses RLS — server code must filter by a verified user id |
| View bypasses RLS | CRITICAL/HIGH | A view readable by `anon`/`authenticated` that is not `security_invoker`: it runs with the owner's rights, so the underlying tables' RLS does not apply |
| Materialized view exposed | CRITICAL/HIGH | Materialized views can't be `security_invoker`; if API roles can select them, their rows have no RLS at all |
| Exposed `SECURITY DEFINER` function | HIGH/MEDIUM/INFO | Callable via `/rest/v1/rpc`, runs as the owner and skips RLS. HIGH if `anon` can call it and the body never references `auth.uid()`; INFO when it does (still: verify) |
| Definer function with mutable `search_path` | MEDIUM/LOW | Unqualified names inside it resolve at call time and can be shadowed |

## Install & run

```bash
npm install
npm run build

# point it at your database (read-only; it only inspects catalogs)
node dist/index.js --url "postgresql://postgres:PASSWORD@db.YOURPROJECT.supabase.co:5432/postgres"

# or
export DATABASE_URL="postgresql://..."
node dist/index.js
```

Get the connection string from **Supabase dashboard → Project Settings →
Database → Connection string (URI)**. The audit runs six `SELECT`s against
the Postgres system catalogs (`pg_class`, `pg_policy`, `pg_attribute`, `pg_proc`,
`information_schema.role_table_grants`). It never reads your table data, and the
session is set to `READ ONLY` at the database level before the first query, so
Postgres itself would reject any write.

## Output formats & CI

```bash
node dist/index.js --format html --out report.html     # shareable HTML report
node dist/index.js --format json --out findings.json    # machine-readable
node dist/index.js --fail-on high                        # exit 1 in CI if any HIGH+
```

Drop the `--fail-on` form into a CI step and a new table that ships without RLS
fails the build instead of leaking in production.

## Notes

- Audits one schema at a time (`--schema`, default `public`).
- "User-owned" is detected by column name (`user_id`, `owner_id`, `profile_id`,
  `account_id`, `uid`, `created_by`, `owner`). Edit `OWNERSHIP_COLUMNS` in
  `src/db.ts` for your own conventions.
- Findings are heuristics over your real policies — a few may be intentional for
  your design (e.g. a deliberately public table). Read each one; it tells you
  what it saw and why.

## Tested against planted leaks

`test/fixture.sql` plants one leak per check (tables, views and `SECURITY DEFINER`
functions) next to correctly secured objects. CI loads it into a real Postgres 17 on
every push, runs the scanner and asserts the known answer (`test/expect.js`).
Measured result:

```
Summary:  3 crit   3 high   3 med   8 low   7 info      Verdict: AT RISK
```

Every planted issue is reported, the `security_invoker` view is not flagged, the correctly secured table gets INFO only and the
`FORCE ROW LEVEL SECURITY` table gets no findings. `--format json`, `--format html`
and `--fail-on high` (exit code 1) were verified by hand on the table cases.

## License

MIT. Built and maintained by [Operon](https://operon-security.vercel.app) — Supabase and Next.js security reviews.
If the scanner finds something and you want a second pair of eyes on the fix, that is what I do.
