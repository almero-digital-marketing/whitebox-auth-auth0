# whitebox-auth-auth0

Auth0 (and generic OIDC) **MCP auth verifier** for WhiteBox. Makes `/mcp` an
OAuth 2.1 Resource Server: it validates the incoming Bearer JWT against the
provider's JWKS and advertises the authorization server so MCP clients can run
the login flow themselves.

```js
import { auth0 } from 'whitebox-auth-auth0'

// whitebox.config.js
mcp: {
  path: '/mcp',
  auth: auth0({
    domain: process.env.AUTH0_DOMAIN,          // your-tenant.auth0.com
    audience: 'https://whitebox/mcp',           // the Auth0 API identifier
    scope: 'mcp:use',                           // optional: required permission
  }),
}
```

It returns a verifier `{ middleware, authorizationServers, resource?, scopesSupported }`
— the contract `whitebox-server`'s `resolveMcpAuth` understands. The core then:

- gates `/mcp` with the JWT-validating middleware, and
- serves `/.well-known/oauth-protected-resource` (RFC 9728) pointing at Auth0,
  and the middleware returns `401` with a `WWW-Authenticate: Bearer
  resource_metadata="…"` header — so a token-less MCP client discovers Auth0 and
  does PKCE login + refresh on its own.

No Auth0 code lives in the core — this is a pure, composable package (its only
dependency is `jose`). `jwt({ issuer, audience, jwksUri, scope })` is the generic
form for any OIDC provider; `auth0()` is a thin wrapper.

## Auth0 setup

1. Create an **API** in Auth0; its identifier is your `audience`. (Tokens are RS256.)
2. (Optional) define **permissions/scopes** (e.g. `mcp:use`) and require one via `scope`.
3. (Optional, recommended for MCP) enable **Dynamic Client Registration** so MCP
   clients self-register; otherwise pre-register a client.

Validation checks signature (JWKS, with key rotation), `iss`, `aud`, and expiry;
`req.auth = { sub, scope, claims }` is attached for downstream per-caller logic.
