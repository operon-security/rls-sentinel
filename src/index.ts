#!/usr/bin/env node
import { parseArgs } from 'node:util'
import { writeFileSync } from 'node:fs'
import { introspect } from './db'
import { audit } from './checks'
import { renderTerminal, renderHtml, renderJson, summarize } from './report'
import { Severity, SEVERITY_ORDER } from './types'

const HELP = `
RLS Sentinel — audit a Supabase / Postgres database for Row Level Security gaps.

Usage:
  rls-sentinel --url <postgres-connection-string> [options]
  DATABASE_URL=... rls-sentinel [options]

Options:
  -u, --url <string>      Postgres connection string. Falls back to $DATABASE_URL.
      --schema <string>   Schema to audit (default: public).
      --format <string>   terminal | html | json  (default: terminal).
      --out <file>        Write the report to a file instead of stdout.
      --fail-on <sev>     Exit 1 if any finding is at or above this severity
                          (critical|high|medium|low). Useful in CI.
  -h, --help              Show this help.

Where to get the connection string:
  Supabase dashboard -> Project Settings -> Database -> Connection string
  (use the "URI" / session pooler value; it already includes your password).
`

function atOrAbove(sev: Severity, threshold: Severity): boolean {
  return SEVERITY_ORDER.indexOf(sev) <= SEVERITY_ORDER.indexOf(threshold)
}

async function main() {
  const { values } = parseArgs({
    options: {
      url: { type: 'string', short: 'u' },
      schema: { type: 'string', default: 'public' },
      format: { type: 'string', default: 'terminal' },
      out: { type: 'string' },
      'fail-on': { type: 'string' },
      help: { type: 'boolean', short: 'h', default: false },
    },
  })

  if (values.help) {
    process.stdout.write(HELP)
    return
  }

  const url = values.url || process.env.DATABASE_URL
  if (!url) {
    process.stderr.write('error: no connection string. Pass --url or set DATABASE_URL.\n')
    process.stderr.write(HELP)
    process.exitCode = 2
    return
  }

  const schema = values.schema || 'public'
  const format = values.format || 'terminal'
  if (!['terminal', 'html', 'json'].includes(format)) {
    process.stderr.write(`error: unknown --format "${format}" (use terminal|html|json)\n`)
    process.exitCode = 2
    return
  }

  // Redact the password from the target label we print/store.
  const target = url.replace(/:\/\/([^:@/]+):[^@]*@/, '://$1:****@')

  let findings
  try {
    const sch = await introspect(url, schema)
    findings = audit(schema, sch)
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e)
    process.stderr.write(`error: could not audit database: ${msg}\n`)
    process.exitCode = 2
    return
  }

  let output: string
  if (format === 'html') output = renderHtml(findings, target)
  else if (format === 'json') output = renderJson(findings, target)
  else output = renderTerminal(findings, target)

  if (values.out) {
    writeFileSync(values.out, output.replace(/\x1b\[[0-9;]*m/g, format === 'terminal' ? '' : ''))
    process.stdout.write(`report written to ${values.out}\n`)
  } else {
    process.stdout.write(output + '\n')
  }

  const failOn = values['fail-on'] as Severity | undefined
  if (failOn) {
    const threshold = failOn.toUpperCase() as Severity
    if (!SEVERITY_ORDER.includes(threshold)) {
      process.stderr.write(`error: unknown --fail-on "${failOn}"\n`)
      process.exitCode = 2
      return
    }
    const breached = findings.some((f) => atOrAbove(f.severity, threshold))
    if (breached) {
      const s = summarize(findings)
      process.stderr.write(`\nfail-on ${threshold}: findings present (score ${s.score}/100). exiting 1.\n`)
      process.exitCode = 1
    }
  }
}

main().catch((e) => {
  process.stderr.write(`fatal: ${e instanceof Error ? e.stack : String(e)}\n`)
  process.exitCode = 2
})
