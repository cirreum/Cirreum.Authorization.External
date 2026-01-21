# Cirreum Authorization Provider - External (BYOID)

[![NuGet Version](https://img.shields.io/nuget/v/Cirreum.Authorization.External.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authorization.External/)
[![NuGet Downloads](https://img.shields.io/nuget/dt/Cirreum.Authorization.External.svg?style=flat-square&labelColor=1F1F1F&color=003D8F)](https://www.nuget.org/packages/Cirreum.Authorization.External/)
[![GitHub Release](https://img.shields.io/github/v/release/cirreum/Cirreum.Authorization.External?style=flat-square&labelColor=1F1F1F&color=FF3B2E)](https://github.com/cirreum/Cirreum.Authorization.External/releases)
[![License](https://img.shields.io/github/license/cirreum/Cirreum.Authorization.External?style=flat-square&labelColor=1F1F1F&color=F2F2F2)](https://github.com/cirreum/Cirreum.Authorization.External/blob/main/LICENSE)
[![.NET](https://img.shields.io/badge/.NET-10.0-003D8F?style=flat-square&labelColor=1F1F1F)](https://dotnet.microsoft.com/)

**Bring Your Own Identity (BYOID) authentication provider for the Cirreum Framework**

## Overview

**Cirreum.Authorization.External** enables your API to accept tokens from multiple customer Identity Providers (Okta, Auth0, customer Entra tenants, etc.) without requiring federation into your identity provider. Tenant IdP configuration is resolved at runtime from a backing store (database, cache, etc.) rather than being statically configured in appsettings.

### Key Features

- **Multi-tenant authentication** - Accept tokens from any customer's IdP
- **Runtime configuration** - Tenant IdP settings resolved from database at request time
- **OIDC discovery** - Automatic JWKS and metadata retrieval per tenant
- **Claim normalization** - Map provider-specific claims to standard claims
- **Defense in depth** - Optional tenant-in-path validation
- **Seamless integration** - Works alongside Entra, ApiKey, and SignedRequest providers

### Use Cases

- B2B SaaS platforms with enterprise customers
- Multi-tenant APIs where each customer uses their own IdP
- Partner integrations with delegated authentication
- Platforms supporting multiple IdP vendors (Okta, Auth0, Azure AD, etc.)

## Installation

```bash
dotnet add package Cirreum.Authorization.External
```

## Configuration

Add External authentication to your `appsettings.json`:

```json
{
  "Cirreum": {
    "Authorization": {
      "Providers": {
        "External": {
          "Instances": {
            "default": {
              "Enabled": true,
              "Scheme": "byoid",
              "TenantIdentifierSource": "Header",
              "TenantHeaderName": "X-Tenant-Slug",
              "TenantNotFoundBehavior": "Reject",
              "ValidateTenantInPath": true,
              "TenantPathSegmentIndex": 0,
              "ValidationPathSegmentIndex": 0,
              "JwksCacheDurationMinutes": 60,
              "ClockSkewSeconds": 300,
              "RequireHttpsMetadata": true,
              "DetailedErrors": false
            }
          }
        }
      }
    }
  }
}
```

### Configuration Properties

| Property | Required | Default | Description |
|----------|----------|---------|-------------|
| `Enabled` | Yes | - | Whether this instance is active |
| `Scheme` | No | `byoid` | Authentication scheme name |
| `TenantIdentifierSource` | No | `Header` | How to extract tenant identifier (`Header`, `PathSegment`, `Subdomain`) |
| `TenantHeaderName` | No | `X-Tenant-Slug` | Header name when using Header source |
| `TenantPathSegmentIndex` | No | `0` | Path segment index when using PathSegment source |
| `TenantNotFoundBehavior` | No | `Reject` | Behavior when tenant not found (`Reject`, `RejectWithLogging`, `Fallback`) |
| `ValidateTenantInPath` | No | `false` | Also validate tenant exists in path (defense in depth) |
| `ValidationPathSegmentIndex` | No | `0` | Path segment index for validation |
| `JwksCacheDurationMinutes` | No | `60` | How long to cache IdP signing keys |
| `ClockSkewSeconds` | No | `300` | Token expiry tolerance in seconds |
| `RequireHttpsMetadata` | No | `true` | Require HTTPS for IdP metadata endpoints |
| `DetailedErrors` | No | `false` | Return detailed error messages (dev only!) |

## Usage

### 1. Implement a Tenant Resolver

```csharp
public class DatabaseTenantResolver : IExternalTenantResolver {
    private readonly MyDbContext _db;

    public DatabaseTenantResolver(MyDbContext db) {
        _db = db;
    }

    public async Task<ExternalTenantConfig?> ResolveAsync(
        ExternalResolutionContext context,
        CancellationToken ct) {

        var tenant = await _db.Tenants
            .FirstOrDefaultAsync(t => t.Slug == context.TenantSlug, ct);

        if (tenant is null) {
            return null;
        }

        return new ExternalTenantConfig {
            Slug = tenant.Slug,
            IsEnabled = tenant.IsEnabled,
            DisplayName = tenant.Name,
            MetadataAddress = tenant.OidcMetadataUrl,
            ValidAudiences = [tenant.Audience],
            AllowedClientIds = tenant.AllowedClientIds,
            RequireAccessTokenType = tenant.RequireAccessTokenType,
            ClaimMappings = tenant.ClaimMappings
        };
    }
}
```

### 2. Register External (BYOID) in Program.cs

```csharp
builder.AddAuthorization(auth => auth
    .AddExternal<DatabaseTenantResolver>(options => options
        .ConfigureOptions(o => {
            // Optional: override appsettings values
            o.TenantIdentifierSource = TenantIdentifierSource.Header;
            o.TenantHeaderName = "X-Tenant-Slug";
        }))
);
```

### 3. Create Policies for BYOID Endpoints

```csharp
builder.AddAuthorization(auth => auth
    .AddExternal<DatabaseTenantResolver>()
)
.AddPolicy("TenantAccess", policy => {
    policy
        .AddAuthenticationSchemes(ExternalDefaults.AuthenticationScheme)
        .RequireAuthenticatedUser()
        .RequireRole("app:user");
});
```

### 4. Apply to Endpoints

```csharp
app.MapGet("/{tenant}/todos", GetTodos)
    .RequireAuthorization("TenantAccess");
```

## Architecture

The provider follows the Cirreum custom scheme authorization pattern:

```text
ExternalAuthorizationRegistrar
└── Extends AuthorizationProviderRegistrar
    ├── Registers ITenantIdentifierExtractor based on TenantIdentifierSource
    ├── Registers IExternalConfigurationManager with caching
    ├── Registers scheme via AuthorizationSchemeRegistry.RegisterCustomScheme()
    └── Configures ExternalAuthenticationHandler

ExternalAuthenticationHandler
├── Extracts tenant identifier via ITenantIdentifierExtractor
├── Resolves tenant config via IExternalTenantResolver
├── Validates token against tenant's IdP using OIDC discovery
├── Normalizes claims using ClaimsHelper
└── Builds ClaimsPrincipal with tenant context
```

### Authentication Flow

1. Request arrives with tenant identifier (header, path segment, or subdomain) and Bearer token
2. `ForwardDefaultSelector` detects tenant identifier + Bearer token and routes to External scheme
3. `ITenantIdentifierExtractor` extracts the tenant slug
4. `IExternalTenantResolver` (your implementation) loads tenant IdP configuration from database
5. `IExternalConfigurationManager` retrieves/caches the tenant's OIDC metadata and JWKS
6. Token is validated against the tenant's IdP signing keys
7. Claims are normalized and `ClaimsPrincipal` is built with tenant context
8. Authorization policies evaluate as normal

### Scheme Selection

Integrates with Cirreum's dynamic scheme selector. The selection priority is:

1. **Conflict detection** - API key header + tenant slug header = reject (ambiguous)
2. **API key header** - Routes to ApiKey scheme
3. **Signed request headers** - Routes to SignedRequest scheme
4. **Tenant identifier + Bearer token** - Routes to External (BYOID) scheme
5. **Bearer token only** - Routes to Entra scheme (by audience)

## Security Considerations

### Tenant Not Found Behavior

| Behavior | Response | Use Case |
|----------|----------|----------|
| `Reject` (default) | 401 | Production - fail closed |
| `RejectWithLogging` | 401 + warning log | Rollout/debugging |
| `Fallback` | Try other schemes | Mixed auth scenarios (use with caution) |

### Defense in Depth

Enable `ValidateTenantInPath` to ensure the tenant identifier in the header matches the path:

```csharp
// Request: GET /acme/todos with X-Tenant-Slug: acme → OK
// Request: GET /acme/todos with X-Tenant-Slug: contoso → 401 (mismatch)
```

### Error Messages

Always set `DetailedErrors = false` in production. Detailed errors can leak information about your authentication structure.

### HTTPS Metadata

Always set `RequireHttpsMetadata = true` in production. This ensures IdP metadata and JWKS are retrieved over secure connections.

### Clock Skew

The default `ClockSkewSeconds` of 300 (5 minutes) provides tolerance for minor time differences. Reduce this value for stricter validation, but be aware of clock drift between systems.

### Token Type Validation

The handler automatically rejects tokens with `typ: "id_token"` - ID tokens should never be used as access tokens. This prevents a class of attacks where an attacker obtains an ID token (easier to acquire) and attempts to use it as a Bearer token.

| `typ` value | `RequireAccessTokenType = false` (default) | `RequireAccessTokenType = true` |
|-------------|-------------------------------------------|--------------------------------|
| `null`/missing | **Rejected** | **Rejected** |
| `id_token` | **Rejected** | **Rejected** |
| `JWT` | Accepted | Rejected |
| `at+jwt` | Accepted | Accepted |

For stricter validation, enable `RequireAccessTokenType` in tenant configuration to require tokens with `typ: "at+jwt"` per RFC 9068:

```csharp
return new ExternalTenantConfig {
    // ...
    RequireAccessTokenType = true // Requires typ: "at+jwt"
};
```

**Note:** Many IdPs still use `typ: "JWT"` for access tokens. Only enable strict mode if you know the tenant's IdP supports RFC 9068.

### Client ID (azp) Validation

Validate the `azp` (Authorized Party) or `client_id` claim to ensure tokens were issued to an expected application. This prevents tokens issued to one client from being used by another:

```csharp
return new ExternalTenantConfig {
    // ...
    AllowedClientIds = ["partner-web-app", "partner-mobile-app"]
};
```

When configured:
- Tokens must contain an `azp` or `client_id` claim
- The claim value must match one of the allowed client IDs
- Tokens from other clients are rejected with 401

This is particularly important when:
- A partner has multiple applications with different trust levels
- You want to restrict which of a partner's apps can call specific endpoints
- You need to prevent lateral movement if one client is compromised

### RFC 9068 / RFC 6750 Compliance

The handler implements JWT access token validation per RFC 9068:

| RFC Requirement | Implementation |
|-----------------|----------------|
| Validate `iss` matches discovery | Yes - exact match required |
| Validate `aud` contains resource server | Yes - must match `ValidAudiences` |
| Validate signature using AS keys | Yes - uses JWKS from OIDC discovery |
| Reject `alg: "none"` | Yes - unsigned tokens always rejected |
| Validate `exp` with clock skew | Yes - configurable via `ClockSkewSeconds` |
| `typ` header validation | Partial - rejects `id_token`, optional strict mode for `at+jwt` |
| RFC 6750 error responses | Yes - returns `error="invalid_token"` |

**Note on `typ` validation:** RFC 9068 requires `typ: "at+jwt"`, but many production IdPs (Azure AD, Okta, Auth0) still emit `typ: "JWT"` for access tokens. We accept both by default for compatibility, with opt-in strict mode via `RequireAccessTokenType`.

## Tenant Database Model

Example tenant entity:

```csharp
public class Tenant {
    public Guid Id { get; set; }
    public required string Slug { get; set; }
    public required string Name { get; set; }
    public required bool IsEnabled { get; set; }

    // OIDC Configuration
    public required string OidcMetadataUrl { get; set; }
    public required string Audience { get; set; }
    public string? IssuerOverride { get; set; }

    // Security Configuration
    public List<string>? AllowedClientIds { get; set; }
    public bool RequireAccessTokenType { get; set; }

    // Optional claim mappings as JSON
    public string? ClaimMappingsJson { get; set; }
}
```

## Recommended Tenant Configurations

### Machine-to-Machine (M2M) Integration

For backend service integrations using OAuth 2.0 Client Credentials flow:

```json
{
  "slug": "partner-backend",
  "displayName": "Partner Corp Backend Services",
  "isEnabled": true,
  "metadataAddress": "https://partner.okta.com/.well-known/openid-configuration",
  "validAudiences": ["api://your-api-resource"],
  "allowedClientIds": ["partner-service-client-id"],
  "requireAccessTokenType": true,
  "claimMappings": null
}
```

**Rationale:**
- `allowedClientIds` - Restricts to specific service account(s). M2M tokens always have `azp`/`client_id`.
- `requireAccessTokenType: true` - Most IdPs emit `at+jwt` for client credentials tokens. Enforces RFC 9068.
- `claimMappings: null` - M2M tokens typically don't need claim normalization.

### Browser/Mobile Client Integration

For user-facing applications using Authorization Code + PKCE flow:

```json
{
  "slug": "partner-app",
  "displayName": "Partner Corp Customer App",
  "isEnabled": true,
  "metadataAddress": "https://partner.auth0.com/.well-known/openid-configuration",
  "validAudiences": ["api://your-api-resource"],
  "allowedClientIds": ["partner-web-app", "partner-mobile-app"],
  "requireAccessTokenType": false,
  "claimMappings": {
    "https://partner.com/roles": "roles",
    "nickname": "name"
  }
}
```

**Rationale:**
- `allowedClientIds` - List all legitimate client apps. Prevents tokens from dev/test apps in production.
- `requireAccessTokenType: false` - Many IdPs still emit `typ: "JWT"` for user access tokens.
- `claimMappings` - Normalize partner-specific claims to standard names your API expects.

### High-Security Financial Partner

For regulated industries requiring maximum security:

```json
{
  "slug": "financial-partner",
  "displayName": "Bank Corp Integration",
  "isEnabled": true,
  "metadataAddress": "https://identity.bankcorp.com/.well-known/openid-configuration",
  "validAudiences": ["api://your-api-resource"],
  "allowedClientIds": ["bankcorp-trading-system"],
  "requireAccessTokenType": true,
  "claimMappings": null
}
```

**Rationale:**
- Single `allowedClientIds` entry - One client per integration for audit trail clarity.
- `requireAccessTokenType: true` - Financial IdPs typically support RFC 9068.
- Consider also using **Signed Request** authentication for request integrity if available.

### Configuration Comparison

| Setting | M2M | Browser/Mobile | High-Security |
|---------|-----|----------------|---------------|
| `allowedClientIds` | Single service ID | Multiple app IDs | Single system ID |
| `requireAccessTokenType` | `true` | `false` | `true` |
| `claimMappings` | Usually none | Often needed | Usually none |
| Token lifetime (IdP side) | 5-15 minutes | 15-60 minutes | 5 minutes |

## Claim Normalization

External uses Cirreum's `ClaimsHelper` for automatic claim normalization across different IdPs. You can also specify custom mappings per tenant:

```csharp
return new ExternalTenantConfig {
    // ...
    ClaimMappings = new Dictionary<string, string> {
        ["groups"] = "roles",           // Okta groups → roles
        ["preferred_username"] = "name" // Custom mapping
    }
};
```

## Caching

- **JWKS caching** - Handled automatically per IdP metadata address (configurable via `JwksCacheDurationMinutes`)
- **Tenant config caching** - Your resolver's responsibility

Example with caching:

```csharp
public class CachedTenantResolver : IExternalTenantResolver {
    private readonly MyDbContext _db;
    private readonly IMemoryCache _cache;

    public async Task<ExternalTenantConfig?> ResolveAsync(
        ExternalResolutionContext context,
        CancellationToken ct) {

        var cacheKey = $"tenant:{context.TenantSlug}";

        if (_cache.TryGetValue<ExternalTenantConfig>(cacheKey, out var config)) {
            return config;
        }

        var tenant = await _db.Tenants
            .FirstOrDefaultAsync(t => t.Slug == context.TenantSlug, ct);

        if (tenant is null) {
            return null;
        }

        config = new ExternalTenantConfig { /* ... */ };

        _cache.Set(cacheKey, config, TimeSpan.FromMinutes(5));

        return config;
    }
}
```

## Accessing Tenant Context

After successful authentication, tenant context is available:

```csharp
app.MapGet("/{tenant}/todos", (HttpContext context) => {
    var tenantSlug = context.Items["External:TenantSlug"] as string;
    var tenantConfig = context.Items["External:TenantConfig"] as ExternalTenantConfig;

    // Or from claims
    var slugClaim = context.User.FindFirst("tenant_slug")?.Value;
});
```

## Claims

Authenticated requests receive the following claims:

| Claim | Value |
|-------|-------|
| `tenant_slug` | The resolved tenant identifier |
| `auth_scheme` | The authentication scheme name (e.g., `byoid`) |
| `idp_type` | The tenant's identity provider type |
| Standard OIDC claims | Normalized from the tenant's IdP token |
| Custom mapped claims | Per tenant `ClaimMappings` configuration |

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

**Cirreum Foundation Framework**
*Layered simplicity for modern .NET*
