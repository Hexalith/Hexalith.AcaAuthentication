namespace Hexalith.AcaAuthentication.Server;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;

internal static class CookieAcaAuthenticationServiceCollectionExtensions
{
    public static IServiceCollection ConfigureCookieAcaAuthenticationRefresh(this IServiceCollection services, string cookieScheme, string AcaAuthenticationScheme)
    {
        _ = services.AddSingleton<CookieAcaAuthenticationRefresher>();
        _ = services.AddOptions<CookieAuthenticationOptions>(cookieScheme).Configure<CookieAcaAuthenticationRefresher>((cookieOptions, refresher) => cookieOptions.Events.OnValidatePrincipal = context => refresher.ValidateOrRefreshCookieAsync(context, AcaAuthenticationScheme));
        _ = services.AddOptions<OpenIdConnectOptions>(AcaAuthenticationScheme).Configure(AcaAuthenticationOptions =>
        {
            // Request a refresh_token.
            AcaAuthenticationOptions.Scope.Add("offline_access");

            // Store the refresh_token.
            AcaAuthenticationOptions.SaveTokens = true;
        });
        return services;
    }
}