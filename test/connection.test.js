// Unit tests for the connection layer: TLS state as pg actually resolves it, and
// the first-run hints. Runs against the built dist/ (npm run build first).
const { test } = require('node:test')
const assert = require('node:assert/strict')
const { Client } = require('pg')
const { tlsState } = require('../dist/db')
const { connectionHint } = require('../dist/hints')

const BASE = 'postgresql://postgres:pw@db.abcdefghijklmnop.supabase.co:5432/postgres'
const POOLER = 'postgresql://postgres.abcdefghijklmnop:pw@aws-0-eu-central-1.pooler.supabase.com:5432/postgres'

// Same default the CLI uses when --ca is not given. Constructing a Client does
// not connect, so this reads pg's real merge of URL + code settings.
const state = (url, ssl = { rejectUnauthorized: false }) => tlsState(new Client({ connectionString: url, ssl }))

test('tlsState: no sslmode in the URL -> encrypted but unverified', () => {
  assert.equal(state(BASE), 'unverified')
})

test('tlsState: sslmode=disable -> off', () => {
  assert.equal(state(BASE + '?sslmode=disable'), 'off')
})

test('tlsState: sslmode=no-verify -> unverified', () => {
  assert.equal(state(BASE + '?sslmode=no-verify'), 'unverified')
})

test('tlsState: sslmode=verify-full -> verified', () => {
  assert.equal(state(BASE + '?sslmode=verify-full'), 'verified')
})

// pg 8 treats require as verify-full. pg 9 is announced to switch to libpq
// semantics (no verification). If that lands, this test fails on purpose: the
// CLI must not keep calling such a connection "verified".
test('tlsState: sslmode=require follows pg 8 (verify-full)', () => {
  assert.equal(state(BASE + '?sslmode=require'), 'verified')
})

test('tlsState: --ca (ca + rejectUnauthorized) -> verified', () => {
  assert.equal(state(BASE, { ca: 'PEM', rejectUnauthorized: true }), 'verified')
})

const err = (code, message = 'boom') => Object.assign(new Error(message), { code })

test('hint: certificate error without --ca points to --ca and sslmode', () => {
  const h = connectionHint(err('SELF_SIGNED_CERT_IN_CHAIN', 'self-signed certificate in certificate chain'), BASE + '?sslmode=require')
  assert.match(h, /--ca/)
  assert.match(h, /sslmode=require as verify-full/)
})

test('hint: certificate error with --ca names the CA file', () => {
  const h = connectionHint(err('UNABLE_TO_VERIFY_LEAF_SIGNATURE', 'unable to verify the first certificate'), BASE, { caFile: 'prod-ca.crt' })
  assert.match(h, /did not verify against prod-ca\.crt/)
})

test('hint: network failure on the Supabase direct host -> IPv6 / session pooler', () => {
  for (const code of ['ENETUNREACH', 'EHOSTUNREACH', 'ETIMEDOUT', 'ENOTFOUND']) {
    assert.match(connectionHint(err(code), BASE), /IPv6-only/, code)
  }
  assert.match(connectionHint(new Error('Connection terminated due to connection timeout'), BASE), /Session pooler/)
})

test('hint: the same network failure on a pooler host gets no IPv6 hint', () => {
  assert.equal(connectionHint(err('ETIMEDOUT'), POOLER), null)
})

test('hint: unrelated errors get no hint', () => {
  assert.equal(connectionHint(err('28P01', 'password authentication failed for user "postgres"'), BASE), null)
})

test('hint: a malformed connection string does not throw', () => {
  assert.equal(connectionHint(err('ETIMEDOUT'), 'not a url'), null)
})
