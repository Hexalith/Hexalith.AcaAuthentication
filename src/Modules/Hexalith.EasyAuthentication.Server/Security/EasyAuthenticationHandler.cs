namespace Hexalith.EasyAuthentication.Server.Security;

using System;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;

using Hexalith.EasyAuthentication.Shared.Configurations;

using Microsoft.AspNetCore.Authentication;

using Microsoft.Extensions.Logging;

using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

/// <summary>
/// Easy authentication handler.
/// </summary>
/// <remarks>
/// Initializes a new instance of the <see cref="EasyAuthenticationHandler"/> class.
/// </remarks>
/// <param name="options">The options for the authentication handler.</param>
/// <param name="logger">The logger factory.</param>
/// <param name="encoder">The URL encoder.</param>
/// <param name="settings">The options for the EasyAuthenticationSettings.</param>
public class EasyAuthenticationHandler(
    IOptionsMonitor<EasyAuthenticationSchemeOptions> options,
    ILoggerFactory logger,
    UrlEncoder encoder,
    IOptions<EasyAuthenticationSettings> settings) : AuthenticationHandler<EasyAuthenticationSchemeOptions>(options, logger, encoder)
{
    private static readonly JsonSerializerOptions _options = new() { PropertyNameCaseInsensitive = true, };

    private readonly EasyAuthenticationSettings _settings = settings.Value;

    /// <summary>
    /// Handles the authentication process for the EasyAuthenticationHandler.
    /// </summary>
    /// <returns>An asynchronous task that represents the authentication result.</returns>
    protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        try
        {
            if (!_settings.Enabled)
            {
                return AuthenticateResult.NoResult();
            }

            ClientPrincipal? clientPrincipal;
            string? easyAuthProvider = Context.Request.Headers["x-ms-client-principal-idp"].FirstOrDefault();
            if (string.IsNullOrWhiteSpace(easyAuthProvider))
            {
                return AuthenticateResult.Fail("Header 'x-ms-client-principal-idp' not found in the request.");
            }

            if (Context.Request.Headers.TryGetValue("x-ms-client-principal", out StringValues header))
            {
                string? data = header[0];
                if (string.IsNullOrWhiteSpace(data))
                {
                    return AuthenticateResult.Fail("Header 'x-ms-client-principal' contains an empty string.");
                }

                byte[] decoded = Convert.FromBase64String(data);
                string json = Encoding.UTF8.GetString(decoded);
                clientPrincipal = JsonSerializer.Deserialize<ClientPrincipal>(json, _options);
                if (clientPrincipal == null)
                {
                    return AuthenticateResult.Fail("Could not deserialize client principal from the x-ms-client-principal header.");
                }
            }
            else
            {
                return AuthenticateResult.Fail("Header 'x-ms-client-principal' not found in the request.");
            }

            IEnumerable<Claim> claims = clientPrincipal.Claims.Select(claim => new Claim(claim.Type, claim.Value));

            // Redefine "roles" claims from easy auth to the standard ClaimTypes.Role "http://schemas.microsoft.com/ws/2008/06/identity/claims/role"
            IEnumerable<Claim> claimsAndRoles = claims
                .Concat(claims
                            .Where(claim => claim.Type == "roles")
                            .Select(role => new Claim(ClaimTypes.Role, role.Value)));

            ClaimsIdentity identity = new(
                claimsAndRoles,
                clientPrincipal.IdentityProvider,
                clientPrincipal.NameClaimType,
                ClaimTypes.Role);

            ClaimsPrincipal claimsPrincipal = new(identity);

            AuthenticationTicket ticket = new(claimsPrincipal, easyAuthProvider);
            AuthenticateResult success = AuthenticateResult.Success(ticket);
            Context.User = claimsPrincipal;

            return await Task.FromResult(success).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            return AuthenticateResult.Fail(ex);
        }
    }
}