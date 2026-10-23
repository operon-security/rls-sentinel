# Security Policy

RLS Sentinel connects to a database with credentials that can read everything,
so the tool's own trustworthiness is part of its job. If you find a way it
behaves worse than it promises, please report it.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting:
**Security → "Report a vulnerability"**
(https://github.com/operon-security/rls-sentinel/security/advisories/new).

That opens a private advisory only the maintainer can see. Please do **not**
open a public issue for a security problem, and please don't report it over
social media or DMs — the private advisory keeps it out of public view until
there is a fix.

Include, as far as you can:

- what you ran (command and flags — redact your connection string and password);
- what happened versus what you expected;
- the PostgreSQL and Node versions, and the pooler / connection mode if relevant;
- a minimal way to reproduce it.

## What counts as a vulnerability here

This is a read-only auditing tool. Treat any of these as a security bug, not
just an ordinary one:

- **It writes to, or changes, the target database.** Every query runs inside
  one read-only transaction that is always rolled back; a statement that
  mutates anything is a vulnerability.
- **It reads your table data.** It should touch only the system catalogs
  (`pg_class`, `pg_policy`, `pg_attribute`, `pg_proc`,
  `information_schema.role_table_grants`), never row data.
- **It leaks the connection string or password** — to stdout, to a report
  file, to logs, or anywhere else.
- **It weakens TLS silently.** With `--ca`, verification must be real; without
  it, every run must say the server was not verified. A path that claims
  "verified" without verifying is a vulnerability.
- **A check reports a genuinely leaky configuration as safe.** A false
  *negative* that gives false assurance is security-relevant — more so than a
  false positive. If you can show a real RLS gap the scanner calls clean, that
  is a report worth making.

## Supported versions

Pre-1.0: only the latest `main` is supported. Fixes land on `main`; there are
no backports yet.

## How it is handled

One maintainer, best effort — no paid SLA, and I would rather be honest about
that than promise a number I cannot hold. Expect an acknowledgement within a
few days. If a report is valid, the fix comes first and the public note
(crediting you, if you want) comes with or after it. If I disagree that
something is a vulnerability, I will say why.
