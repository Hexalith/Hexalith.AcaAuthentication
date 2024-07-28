namespace Hexalith.AzureContainerAppAuthentication.Server;

using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

/// <summary>
/// https://github.com/dotnet/aspnetcore/issues/8175.
/// </summary>
/// <param name="AzureContainerAppAuthenticationOptionsMonitor">AzureContainerAppAuthentication options.</param>
internal sealed class CookieAzureContainerAppAuthenticationRefresher(IOptionsMonitor<OpenIdConnectOptions> AzureContainerAppAuthenticationOptionsMonitor) : IDisposable
{
    private readonly OpenIdConnectProtocolValidator _AzureContainerAppAuthenticationTokenValidator = new()
    {
        // Refresh requests do not use the nonce parameter. Otherwise, we'd use AzureContainerAppAuthenticationOptions.ProtocolValidator.
        RequireNonce = false,
    };

    private readonly HttpClient _refreshClient = new();

    /// <inheritdoc/>
    public void Dispose() => _refreshClient.Dispose();

    /// <summary>
    /// Validates or refreshes the cookie.
    /// </summary>
    /// <param name="validateContext">The context.</param>
    /// <param name="AzureContainerAppAuthenticationScheme">The AzureContainerAppAuthentication scheme.</param>
    /// <returns>The tesk.</returns>
    /// <exception cref="InvalidOperationException"></exception>
    internal async Task ValidateOrRefreshCookieAsync(CookieValidatePrincipalContext validateContext, string AzureContainerAppAuthenticationScheme)
    {
        string? accessTokenExpirationText = validateContext.Properties.GetTokenValue("expires_at");
        if (!DateTimeOffset.TryParse(
            accessTokenExpirationText,
            CultureInfo.InvariantCulture,
            out DateTimeOffset accessTokenExpiration))
        {
            return;
        }

        OpenIdConnectOptions AzureContainerAppAuthenticationOptions = AzureContainerAppAuthenticationOptionsMonitor.Get(AzureContainerAppAuthenticationScheme);
        DateTimeOffset now = AzureContainerAppAuthenticationOptions.TimeProvider!.GetUtcNow();
        if (now + TimeSpan.FromMinutes(5) < accessTokenExpiration)
        {
            return;
        }

        const string refreshTokenName = "refresh_token";
        OpenIdConnectConfiguration AzureContainerAppAuthenticationConfiguration = await AzureContainerAppAuthenticationOptions.ConfigurationManager!.GetConfigurationAsync(validateContext.HttpContext.RequestAborted).ConfigureAwait(false);
        string tokenEndpoint = AzureContainerAppAuthenticationConfiguration.TokenEndpoint ?? throw new InvalidOperationException("Cannot refresh cookie. TokenEndpoint missing!");
        using FormUrlEncodedContent formUrlEncoded = new(new Dictionary<string, string?>
        {
            ["grant_type"] = refreshTokenName,
            ["client_id"] = AzureContainerAppAuthenticationOptions.ClientId,
            ["client_secret"] = AzureContainerAppAuthenticationOptions.ClientSecret,
            ["scope"] = string.Join(" ", AzureContainerAppAuthenticationOptions.Scope),
            [refreshTokenName] = validateContext.Properties.GetTokenValue(refreshTokenName),
        });
        using HttpResponseMessage refreshResponse = await _refreshClient.PostAsync(
            new Uri(tokenEndpoint),
            formUrlEncoded)
            .ConfigureAwait(false);

        if (!refreshResponse.IsSuccessStatusCode)
        {
            validateContext.RejectPrincipal();
            return;
        }

        string refreshJson = await refreshResponse.Content.ReadAsStringAsync().ConfigureAwait(false);
        OpenIdConnectMessage message = new(refreshJson);

        TokenValidationParameters validationParameters = AzureContainerAppAuthenticationOptions.TokenValidationParameters.Clone();
        if (AzureContainerAppAuthenticationOptions.ConfigurationManager is BaseConfigurationManager baseConfigurationManager)
        {
            validationParameters.ConfigurationManager = baseConfigurationManager;
        }
        else
        {
            validationParameters.ValidIssuer = AzureContainerAppAuthenticationConfiguration.Issuer;
            validationParameters.IssuerSigningKeys = AzureContainerAppAuthenticationConfiguration.SigningKeys;
        }

        TokenValidationResult validationResult = await AzureContainerAppAuthenticationOptions.TokenHandler.ValidateTokenAsync(message.IdToken, validationParameters).ConfigureAwait(false);

        if (!validationResult.IsValid)
        {
            validateContext.RejectPrincipal();
            return;
        }

        _AzureContainerAppAuthenticationTokenValidator.ValidateTokenResponse(new()
        {
            ProtocolMessage = message,
            ClientId = AzureContainerAppAuthenticationOptions.ClientId,
            ValidatedIdToken = JwtSecurityTokenConverter.Convert(validationResult.SecurityToken as JsonWebToken),
        });

        validateContext.ShouldRenew = true;
        validateContext.ReplacePrincipal(new ClaimsPrincipal(validationResult.ClaimsIdentity));

        int expiresIn = int.Parse(message.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture);
        DateTimeOffset expiresAt = now + TimeSpan.FromSeconds(expiresIn);
        validateContext.Properties.StoreTokens([
            new() { Name = "access_token", Value = message.AccessToken },
            new() { Name = "id_token", Value = message.IdToken },
            new() { Name = refreshTokenName, Value = message.RefreshToken },
            new() { Name = "token_type", Value = message.TokenType },
            new() { Name = "expires_at", Value = expiresAt.ToString("o", CultureInfo.InvariantCulture) },
        ]);
    }
}