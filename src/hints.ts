// Turns the first-run connection failures we know about into one actionable line.
// Pure: error + connection string in, hint (or null) out. Anything unrecognised
// gets no hint — a wrong hint is worse than none.

const CERT_CODES = new Set([
  'SELF_SIGNED_CERT_IN_CHAIN',
  'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
  'ERR_TLS_CERT_ALTNAME_INVALID',
  'CERT_HAS_EXPIRED',
])

const NETWORK_CODES = new Set(['ENETUNREACH', 'EHOSTUNREACH', 'ETIMEDOUT', 'ENOTFOUND', 'EAI_AGAIN', 'EADDRNOTAVAIL'])

// Supabase's direct host. The poolers (*.pooler.supabase.com) speak IPv4.
const SUPABASE_DIRECT_HOST = /^db\.[a-z0-9]+\.supabase\.co$/i

function hostOf(connectionString: string): string | null {
  try {
    return new URL(connectionString).hostname || null
  } catch {
    return null
  }
}

export function connectionHint(
  err: unknown,
  connectionString: string,
  opts: { caFile?: string } = {}
): string | null {
  const code = (err as { code?: unknown } | null)?.code
  const message = err instanceof Error ? err.message : String(err)

  if ((typeof code === 'string' && CERT_CODES.has(code)) || /certificate/i.test(message)) {
    if (opts.caFile) {
      return (
        `hint: the server certificate did not verify against ${opts.caFile}. Check that it is ` +
        "your project's CA (Supabase: Project Settings -> Database -> SSL Configuration -> " +
        'Download certificate) and that the host in the URL is the one the certificate names.'
      )
    }
    return (
      "hint: pg treats sslmode=require as verify-full, and Supabase's CA is not in Node's " +
      "trust store. Either pass --ca <your project's CA file> and drop sslmode from the URL, " +
      'or drop sslmode to connect encrypted without verifying the server.'
    )
  }

  const host = hostOf(connectionString)
  const network = (typeof code === 'string' && NETWORK_CODES.has(code)) || /timeout/i.test(message)
  if (host && SUPABASE_DIRECT_HOST.test(host) && network) {
    return (
      'hint: the direct host db.<ref>.supabase.co is IPv6-only unless the project has the ' +
      'IPv4 add-on. On an IPv4 network use the Session pooler connection string instead ' +
      '(Supabase dashboard -> Connect -> Session pooler).'
    )
  }

  return null
}
