namespace Cirreum.Authorization.External;

using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;

/// <summary>
/// Helper methods for BYOID scheme selection in the ForwardDefaultSelector.
/// </summary>
public static class ExternalSchemeSelector {

	/// <summary>
	/// Check if the request should be handled by the BYOID scheme.
	/// </summary>
	/// <param name="context">The HTTP context.</param>
	/// <param name="options">The BYOID options (can be null if BYOID not configured).</param>
	/// <returns>True if this request has BYOID indicators.</returns>
	public static bool ShouldHandleRequest(HttpContext context, ExternalAuthenticationOptions? options) {
		if (options is null) {
			return false;
		}

		// Must have tenant identifier AND bearer token
		var hasTenantIdentifier = HasTenantIdentifier(context, options);
		var hasBearerToken = HasBearerToken(context);

		return hasTenantIdentifier && hasBearerToken;
	}

	/// <summary>
	/// Check if the request has a tenant identifier.
	/// </summary>
	public static bool HasTenantIdentifier(HttpContext context, ExternalAuthenticationOptions options) {
		return options.TenantIdentifierSource switch {
			TenantIdentifierSource.Header => context.Request.Headers.ContainsKey(options.TenantHeaderName),
			TenantIdentifierSource.PathSegment => HasPathSegment(context, options.TenantPathSegmentIndex),
			TenantIdentifierSource.Subdomain => HasSubdomain(context),
			_ => false
		};
	}

	/// <summary>
	/// Check if the request has a bearer token.
	/// </summary>
	public static bool HasBearerToken(HttpContext context) {
		var authHeader = context.Request.Headers[HeaderNames.Authorization].ToString();
		return !string.IsNullOrEmpty(authHeader) &&
			   authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase);
	}

	/// <summary>
	/// Check if the request has conflicting authentication indicators.
	/// </summary>
	/// <param name="context">The HTTP context.</param>
	/// <param name="options">The BYOID options.</param>
	/// <param name="apiKeyHeaderNames">Header names used for API key authentication.</param>
	/// <returns>True if there are conflicting indicators (e.g., both API key and tenant slug headers).</returns>
	public static bool HasConflictingIndicators(
		HttpContext context,
		ExternalAuthenticationOptions options,
		IEnumerable<string> apiKeyHeaderNames) {

		// If tenant identifier is in a header, check for API key header conflict
		if (options.TenantIdentifierSource == TenantIdentifierSource.Header) {
			var hasTenantHeader = context.Request.Headers.ContainsKey(options.TenantHeaderName);
			var hasApiKeyHeader = apiKeyHeaderNames.Any(h => context.Request.Headers.ContainsKey(h));

			// Both tenant slug header AND API key header = conflict
			return hasTenantHeader && hasApiKeyHeader;
		}

		// Path/subdomain tenant identifier doesn't conflict with API key
		return false;

	}

	private static bool HasPathSegment(HttpContext context, int index) {
		var path = context.Request.Path.Value;
		if (string.IsNullOrEmpty(path)) {
			return false;
		}

		var segments = path.TrimStart('/').Split('/', StringSplitOptions.RemoveEmptyEntries);
		return index >= 0 && index < segments.Length;

	}

	private static bool HasSubdomain(HttpContext context) {
		var host = context.Request.Host.Host;
		if (string.IsNullOrEmpty(host)) {
			return false;
		}

		var parts = host.Split('.');
		if (parts.Length < 2) {
			return false;
		}

		// Skip "www"
		var subdomain = parts[0];
		return !subdomain.Equals("www", StringComparison.OrdinalIgnoreCase);

	}

}