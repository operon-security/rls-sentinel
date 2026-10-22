// Asserts the scanner's JSON output on test/fixture.sql against the known answer.
// Usage: node test/expect.js report.json
const fs = require('fs')
const r = JSON.parse(fs.readFileSync(process.argv[2], 'utf8'))
const bySev = {}, byCheck = {}
for (const f of r.findings) {
  bySev[f.severity] = (bySev[f.severity] || 0) + 1
  const k = `${f.check}:${f.table ?? '-'}`
  byCheck[k] = (byCheck[k] || 0) + 1
}
const want = { CRITICAL: 3, HIGH: 3, MEDIUM: 3, LOW: 8, INFO: 7 }
const mustHave = [
  'RLS_DISABLED:t_rls_off', 'POLICY_UNRESTRICTED:t_using_true', 'POLICY_LOGGED_IN_ONLY:t_logged_in',
  'WITH_CHECK_UNRESTRICTED:t_insert_open', 'NULLABLE_OWNER:t_nullable_owner', 'RLS_NO_POLICY:t_no_policy',
  'VIEW_BYPASSES_RLS:v_leak', 'DEFINER_FUNCTION_EXPOSED:-', 'DEFINER_SEARCH_PATH:-',
]
const mustNot = ['VIEW_BYPASSES_RLS:v_ok']
let ok = true
for (const s of Object.keys(want)) {
  const got = bySev[s] || 0
  console.log(`${s.padEnd(8)} want ${want[s]}  got ${got}${got === want[s] ? '' : '   <-- MISMATCH'}`)
  if (got !== want[s]) ok = false
}
for (const k of mustHave) if (!byCheck[k]) { console.log('missing: ' + k); ok = false }
for (const k of mustNot) if (byCheck[k]) { console.log('unexpected: ' + k); ok = false }
const forced = r.findings.filter((f) => f.table === 't_forced')
if (forced.length) { console.log('t_forced should have no findings, got ' + forced.length); ok = false }
console.log(ok ? 'FIXTURE OK' : 'FIXTURE FAILED')
process.exit(ok ? 0 : 1)
