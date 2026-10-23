// Unit tests for grant-aware severity (22 Eki — R3 bulgusu).
// A permissive policy (USING true / logged-in-only) is only a real leak if the
// table is actually granted to a client role. Severity must reflect reachability.
const { test } = require('node:test')
const assert = require('node:assert/strict')
const { audit } = require('../dist/checks')

const emptySchema = () => ({ tables: [], policies: [], grants: [], ownerColumns: [], views: [], definerFunctions: [] })

const withUsingTrue = (granted) => {
  const s = emptySchema()
  s.tables.push({ table: 't', rlsEnabled: true, rlsForced: true }) // forced → no RLS_NOT_FORCED noise
  s.policies.push({ table: 't', name: 'p', cmd: 'SELECT', usingExpr: 'true', checkExpr: null, roles: ['anon'] })
  if (granted) s.grants.push({ table: 't', grantee: 'anon', privilege: 'SELECT' })
  return s
}

test('POLICY_UNRESTRICTED is CRITICAL when the table IS granted to anon', () => {
  const f = audit('public', withUsingTrue(true)).find((x) => x.check === 'POLICY_UNRESTRICTED')
  assert.ok(f, 'finding present')
  assert.equal(f.severity, 'CRITICAL')
})

test('POLICY_UNRESTRICTED drops to LOW when the table is NOT granted (not reachable)', () => {
  const f = audit('public', withUsingTrue(false)).find((x) => x.check === 'POLICY_UNRESTRICTED')
  assert.ok(f, 'still reported (a later GRANT makes it critical)')
  assert.equal(f.severity, 'LOW')
  assert.match(f.detail, /not reachable/)
})

const withLoggedInOnly = (granted) => {
  const s = emptySchema()
  s.tables.push({ table: 't', rlsEnabled: true, rlsForced: true })
  s.policies.push({ table: 't', name: 'p', cmd: 'SELECT', usingExpr: 'auth.uid() is not null', checkExpr: null, roles: ['authenticated'] })
  if (granted) s.grants.push({ table: 't', grantee: 'authenticated', privilege: 'SELECT' })
  return s
}

test('POLICY_LOGGED_IN_ONLY is HIGH when granted, LOW when not reachable', () => {
  assert.equal(audit('public', withLoggedInOnly(true)).find((x) => x.check === 'POLICY_LOGGED_IN_ONLY').severity, 'HIGH')
  assert.equal(audit('public', withLoggedInOnly(false)).find((x) => x.check === 'POLICY_LOGGED_IN_ONLY').severity, 'LOW')
})
