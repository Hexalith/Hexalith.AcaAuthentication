namespace Hexalith.AzureContainerAppAuthentication.Server;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;

internal static class CookieAzureContainerAppAuthenticationServiceCollectionExtensions
{
    public static IServiceCollection ConfigureCookieAzureContainerAppAuthenticationRefresh(this IServiceCollection services, string cookieScheme, string AzureContainerAppAuthenticationScheme)
    {
        _ = services.AddSingleton<CookieAzureContainerAppAuthenticationRefresher>();
        _ = services.AddOptions<CookieAuthenticationOptions>(cookieScheme).Configure<CookieAzureContainerAppAuthenticationRefresher>((cookieOptions, refresher) => cookieOptions.Events.OnValidatePrincipal = context => refresher.ValidateOrRefreshCookieAsync(context, AzureContainerAppAuthenticationScheme));
        _ = services.AddOptions<OpenIdConnectOptions>(AzureContainerAppAuthenticationScheme).Configure(AzureContainerAppAuthenticationOptions =>
        {
            // Request a refresh_token.
            AzureContainerAppAuthenticationOptions.Scope.Add("offline_access");

            // Store the refresh_token.
            AzureContainerAppAuthenticationOptions.SaveTokens = true;
        });
        return services;
    }
}