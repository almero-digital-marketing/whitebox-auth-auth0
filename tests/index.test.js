import { describe, it, expect, vi, beforeEach } from 'vitest'

// Mock jose so we don't need a real Auth0 tenant.
vi.mock('jose', () => ({ createRemoteJWKSet: () => ({}), jwtVerify: vi.fn() }))

const { jwtVerify } = await import('jose')
const { auth0, jwt } = await import('../src/index.js')

async function call(mw, authHeader) {
  const req = { protocol: 'https', headers: { host: 'go.x', ...(authHeader ? { authorization: authHeader } : {}) }, get(n) { return this.headers[n.toLowerCase()] } }
  const res = {
    statusCode: 200, body: null, _headers: {},
    set(k, v) { this._headers[k] = v; return this },
    status(s) { this.statusCode = s; return this },
    json(b) { this.body = b; return this },
  }
  const next = vi.fn()
  try { await mw(req, res, next) } catch (e) { res._threw = e }
  return { req, res, next }
}

beforeEach(() => jwtVerify.mockReset())

describe('auth0 verifier', () => {
  it('exposes the verifier contract (AS derived from domain)', () => {
    const v = auth0({ domain: 'tenant.auth0.com', audience: 'https://whitebox/mcp', scope: 'mcp:use' })
    expect(typeof v.middleware).toBe('function')
    expect(v.authorizationServers).toEqual(['https://tenant.auth0.com/'])
    expect(v.scopesSupported).toEqual(['mcp:use'])
  })

  it('throws without a domain', () => {
    expect(() => auth0({ audience: 'x' })).toThrow(/domain/)
  })

  it('rejects a missing token with 401 + WWW-Authenticate discovery', async () => {
    const v = auth0({ domain: 't.auth0.com', audience: 'a' })
    const { res, next } = await call(v.middleware, undefined)
    expect(res.statusCode).toBe(401)
    expect(res._headers['WWW-Authenticate']).toContain('resource_metadata="https://go.x/.well-known/oauth-protected-resource"')
    expect(next).not.toHaveBeenCalled()
  })

  it('accepts a valid token and attaches req.auth', async () => {
    jwtVerify.mockResolvedValue({ payload: { sub: 'auth0|jane', scope: 'mcp:use other' } })
    const v = auth0({ domain: 't.auth0.com', audience: 'a', scope: 'mcp:use' })
    const { req, res, next } = await call(v.middleware, 'Bearer good')
    expect(next).toHaveBeenCalled()
    expect(res.statusCode).toBe(200)
    expect(req.auth).toMatchObject({ sub: 'auth0|jane' })
  })

  it('403s when the required scope is missing', async () => {
    jwtVerify.mockResolvedValue({ payload: { sub: 'x', scope: 'something_else' } })
    const v = auth0({ domain: 't.auth0.com', audience: 'a', scope: 'mcp:use' })
    const { res } = await call(v.middleware, 'Bearer good')
    expect(res.statusCode).toBe(403)
    expect(res.body).toMatchObject({ error: 'insufficient_scope' })
  })
})

describe('jwt (generic OIDC)', () => {
  it('requires issuer + audience', () => {
    expect(() => jwt({ audience: 'a' })).toThrow(/issuer/)
  })
})
