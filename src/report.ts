import { Finding, Severity, SEVERITY_ORDER } from './types'

const ANSI: Record<Severity, string> = {
  CRITICAL: '\x1b[41m\x1b[97m', // white on red
  HIGH: '\x1b[91m', // bright red
  MEDIUM: '\x1b[93m', // yellow
  LOW: '\x1b[96m', // cyan
  INFO: '\x1b[90m', // grey
}
const RESET = '\x1b[0m'
const BOLD = '\x1b[1m'
const DIM = '\x1b[2m'

export type Verdict = 'CLEAN' | 'STRONG' | 'GOOD' | 'NEEDS WORK' | 'AT RISK'

export interface Summary {
  counts: Record<Severity, number>
  total: number
  score: number // 0-100, 100 = clean
  verdict: Verdict
}

const WEIGHT: Record<Severity, number> = {
  CRITICAL: 40,
  HIGH: 18,
  MEDIUM: 4,
  LOW: 1.5,
  INFO: 0,
}

export function summarize(findings: Finding[]): Summary {
  const counts: Record<Severity, number> = {
    CRITICAL: 0,
    HIGH: 0,
    MEDIUM: 0,
    LOW: 0,
    INFO: 0,
  }
  for (const f of findings) counts[f.severity]++

  // Diminishing returns per check: ten tables sharing one issue pattern is one
  // kind of problem repeated, not ten independent catastrophes. First instance
  // of a check counts full weight, each additional instance at half weight.
  const groups = new Map<string, { severity: Severity; n: number }>()
  for (const f of findings) {
    const g = groups.get(f.check)
    if (g) g.n++
    else groups.set(f.check, { severity: f.severity, n: 1 })
  }
  let penalty = 0
  for (const g of groups.values()) {
    penalty += WEIGHT[g.severity] * (1 + 0.5 * (g.n - 1))
  }
  let score = Math.round(Math.max(0, 100 - penalty))

  // The top severity present governs the headline band: a database with any
  // critical finding cannot read as "secure", however few other issues it has.
  if (counts.CRITICAL > 0) score = Math.min(score, 45)
  else if (counts.HIGH > 0) score = Math.min(score, 72)

  const verdict: Verdict =
    counts.CRITICAL > 0
      ? 'AT RISK'
      : counts.HIGH > 0
        ? 'NEEDS WORK'
        : counts.MEDIUM > 0
          ? 'GOOD'
          : counts.LOW > 0
            ? 'STRONG'
            : 'CLEAN'

  return { counts, total: findings.length, score, verdict }
}

function sortFindings(findings: Finding[]): Finding[] {
  const rank = (s: Severity) => SEVERITY_ORDER.indexOf(s)
  return [...findings].sort((a, b) => {
    if (a.severity !== b.severity) return rank(a.severity) - rank(b.severity)
    return (a.table ?? '').localeCompare(b.table ?? '')
  })
}

export function renderTerminal(findings: Finding[], target: string): string {
  const s = summarize(findings)
  const lines: string[] = []
  lines.push('')
  lines.push(`${BOLD}  RLS Sentinel${RESET} ${DIM}— Supabase / Postgres security audit${RESET}`)
  lines.push(`${DIM}  target: ${target}${RESET}`)
  lines.push('')

  const VERDICT_ANSI: Record<string, string> = {
    'AT RISK': ANSI.CRITICAL,
    'NEEDS WORK': ANSI.HIGH,
    GOOD: ANSI.MEDIUM,
    STRONG: ANSI.LOW,
    CLEAN: '\x1b[92m',
  }

  if (findings.length === 0) {
    lines.push(`  \x1b[92m✓ CLEAN — no findings. Score 100/100.${RESET}`)
    lines.push('')
    return lines.join('\n')
  }

  for (const f of sortFindings(findings)) {
    const tag = `${ANSI[f.severity]} ${f.severity} ${RESET}`
    const where = f.table ? `${BOLD}${f.table}${RESET}` : `${DIM}schema${RESET}`
    lines.push(`  ${tag} ${where} — ${f.title}`)
    lines.push(`      ${DIM}${f.detail}${RESET}`)
    lines.push(`      ${DIM}fix:${RESET} ${f.remediation}`)
    lines.push('')
  }

  const c = s.counts
  lines.push(
    `  ${BOLD}Summary:${RESET} ` +
      `${ANSI.CRITICAL} ${c.CRITICAL} crit ${RESET} ` +
      `${ANSI.HIGH}${c.HIGH} high${RESET}  ` +
      `${ANSI.MEDIUM}${c.MEDIUM} med${RESET}  ` +
      `${ANSI.LOW}${c.LOW} low${RESET}  ` +
      `${ANSI.INFO}${c.INFO} info${RESET}`
  )
  const vtag = `${VERDICT_ANSI[s.verdict] ?? ''} ${s.verdict} ${RESET}`
  lines.push(`  ${BOLD}Verdict:${RESET} ${vtag}   ${BOLD}Score: ${s.score}/100${RESET}`)
  if (s.counts.CRITICAL === 0 && s.counts.HIGH === 0) {
    lines.push(`  ${DIM}No critical or high findings — no data-leak vulnerabilities.${RESET}`)
  }
  lines.push('')
  return lines.join('\n')
}

export function renderJson(findings: Finding[], target: string): string {
  return JSON.stringify(
    { target, generatedAt: new Date().toISOString(), summary: summarize(findings), findings: sortFindings(findings) },
    null,
    2
  )
}

const SEV_COLOR: Record<Severity, string> = {
  CRITICAL: '#b91c1c',
  HIGH: '#dc2626',
  MEDIUM: '#d97706',
  LOW: '#0891b2',
  INFO: '#64748b',
}

function esc(x: string): string {
  return x.replace(/[&<>"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[c]!))
}

export function renderHtml(findings: Finding[], target: string): string {
  const s = summarize(findings)
  const rows = sortFindings(findings)
    .map(
      (f) => `
      <tr>
        <td><span class="sev" style="background:${SEV_COLOR[f.severity]}">${f.severity}</span></td>
        <td class="tbl">${f.table ? esc(f.table) : '—'}</td>
        <td>
          <div class="title">${esc(f.title)}</div>
          <div class="detail">${esc(f.detail)}</div>
          <code class="fix">${esc(f.remediation)}</code>
        </td>
      </tr>`
    )
    .join('')

  const clean = findings.length === 0
  const VERDICT_COLOR: Record<string, string> = {
    'AT RISK': '#b91c1c',
    'NEEDS WORK': '#dc2626',
    GOOD: '#16a34a',
    STRONG: '#15803d',
    CLEAN: '#3fe0b0',
  }
  const vColor = VERDICT_COLOR[s.verdict] ?? '#64748b'
  const noLeak = s.counts.CRITICAL === 0 && s.counts.HIGH === 0
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>RLS Sentinel report</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 15px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; margin: 0; background: #0f1115; color: #e7ebf0; }
  .wrap { max-width: 920px; margin: 0 auto; padding: 32px 20px 64px; }
  h1 { margin: 0 0 4px; font-size: 22px; }
  .sub { color: #8b94a3; font-size: 13px; margin-bottom: 24px; word-break: break-all; }
  .verdictrow { display: flex; align-items: baseline; gap: 16px; flex-wrap: wrap; }
  .verdict { display: inline-block; border-radius: 8px; padding: 6px 14px; font-size: 15px; font-weight: 800; color: #fff; letter-spacing: .04em; }
  .score { font-size: 40px; font-weight: 800; }
  .noleak { color: #3fe0b0; font-size: 14px; font-weight: 600; margin: 10px 0 0; }
  .chips { display: flex; gap: 8px; flex-wrap: wrap; margin: 16px 0 28px; }
  .chip { border-radius: 999px; padding: 4px 12px; font-size: 13px; font-weight: 600; color: #fff; }
  table { width: 100%; border-collapse: collapse; }
  td { border-top: 1px solid #262b36; padding: 14px 10px; vertical-align: top; }
  .sev { display: inline-block; border-radius: 6px; padding: 2px 8px; font-size: 11px; font-weight: 700; color: #fff; letter-spacing: .03em; }
  .tbl { font-family: ui-monospace, monospace; font-size: 13px; color: #cbd3df; white-space: nowrap; }
  .title { font-weight: 600; }
  .detail { color: #9aa4b2; font-size: 13px; margin: 4px 0 8px; }
  .fix { display: block; background: #171a21; border: 1px solid #262b36; border-radius: 6px; padding: 8px 10px; font-size: 12px; color: #3fe0b0; overflow-x: auto; }
  .clean { color: #3fe0b0; font-size: 18px; font-weight: 600; }
</style></head>
<body><div class="wrap">
  <h1>RLS Sentinel — security report</h1>
  <div class="sub">Target: ${esc(target)} · ${esc(new Date().toISOString())}</div>
  <div class="verdictrow">
    <span class="verdict" style="background:${vColor}">${s.verdict}</span>
    <span class="score" style="color:${vColor}">${s.score}<span style="font-size:18px;color:#8b94a3">/100</span></span>
  </div>
  ${noLeak ? '<p class="noleak">✓ No critical or high findings — no data-leak vulnerabilities.</p>' : ''}
  <div class="chips">
    <span class="chip" style="background:${SEV_COLOR.CRITICAL}">${s.counts.CRITICAL} critical</span>
    <span class="chip" style="background:${SEV_COLOR.HIGH}">${s.counts.HIGH} high</span>
    <span class="chip" style="background:${SEV_COLOR.MEDIUM}">${s.counts.MEDIUM} medium</span>
    <span class="chip" style="background:${SEV_COLOR.LOW}">${s.counts.LOW} low</span>
    <span class="chip" style="background:${SEV_COLOR.INFO}">${s.counts.INFO} info</span>
  </div>
  ${clean ? '<p class="clean">✓ No findings. RLS posture looks solid.</p>' : `<table><tbody>${rows}</tbody></table>`}
</div></body></html>`
}
