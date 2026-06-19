// Auth0 / generic-OIDC MCP auth verifier.
//
// Makes the MCP endpoint an OAuth 2.1 Resource Server: it validates the incoming
// Bearer JWT against the provider's JWKS (signature + issuer + audience + expiry)
// and advertises the authorization server for discovery. Compose it into config:
//
//   import { auth0 } from 'whitebox-pro-auth-auth0'
//   mcp: { auth: auth0({ domain: 'YOUR.auth0.com', audience: 'https://whitebox/mcp', scope: 'mcp:use' }) }
//
// Implements the WhiteBox auth-verifier contract (whitebox-pro-server/auth):
//   { middleware, authorizationServers, resource?, scopesSupported }

import { createRemoteJWKSet, jwtVerify } from 'jose'

const PROTECTED_RESOURCE = '/.well-known/oauth-protected-resource'

// Generic OIDC verifier — any provider exposing JWKS + standard claims.
export function jwt({ issuer, audience, jwksUri, scope, authorizationServers, resource } = {}) {
  if (!issuer || !audience) throw new Error('jwt(): issuer and audience are required')
  const JWKS = createRemoteJWKSet(new URL(jwksUri || `${issuer.replace(/\/$/, '')}/.well-known/jwks.json`))

  const middleware = async (req, res, next) => {
    const challenge = () => {
      const origin = `${req.protocol}://${req.get('host')}`
      res.set('WWW-Authenticate', `Bearer resource_metadata="${origin}${PROTECTED_RESOURCE}"`)
    }
    const m = /^Bearer\s+(.+)$/i.exec(req.get('authorization') || '')
    if (!m) { challenge(); return res.status(401).json({ error: 'Unauthorized' }) }
    try {
      const { payload } = await jwtVerify(m[1], JWKS, { issuer, audience })
      if (scope && !String(payload.scope || '').split(' ').includes(scope)) {
        return res.status(403).json({ error: 'insufficient_scope', scope })
      }
      req.auth = { sub: payload.sub, scope: payload.scope, claims: payload }
      next()
    } catch {
      challenge(); return res.status(401).json({ error: 'invalid_token' })
    }
  }

  return {
    middleware,
    authorizationServers: authorizationServers || [issuer],
    resource,
    scopesSupported: scope ? [scope] : [],
  }
}

// Auth0 convenience — derives issuer + JWKS from the tenant domain.
export function auth0({ domain, audience, scope, resource } = {}) {
  if (!domain) throw new Error('auth0(): domain is required (e.g. your-tenant.auth0.com)')
  const issuer = `https://${domain}/`
  return jwt({ issuer, audience, jwksUri: `${issuer}.well-known/jwks.json`, scope, resource })
}
