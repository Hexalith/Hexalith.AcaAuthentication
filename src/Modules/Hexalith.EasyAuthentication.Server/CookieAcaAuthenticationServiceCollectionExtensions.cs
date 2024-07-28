namespace Hexalith.EasyAuthentication.Server;

using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.DependencyInjection;

internal static class CookieEasyAuthenticationServiceCollectionExtensions
{
    public static IServiceCollection ConfigureCookieEasyAuthenticationRefresh(this IServiceCollection services, string cookieScheme, string EasyAuthenticationScheme)
    {
        _ = services.AddSingleton<CookieEasyAuthenticationRefresher>();
        _ = services.AddOptions<CookieAuthenticationOptions>(cookieScheme).Configure<CookieEasyAuthenticationRefresher>((cookieOptions, refresher) => cookieOptions.Events.OnValidatePrincipal = context => refresher.ValidateOrRefreshCookieAsync(context, EasyAuthenticationScheme));
        _ = services.AddOptions<OpenIdConnectOptions>(EasyAuthenticationScheme).Configure(EasyAuthenticationOptions =>
        {
            // Request a refresh_token.
            EasyAuthenticationOptions.Scope.Add("offline_access");

            // Store the refresh_token.
            EasyAuthenticationOptions.SaveTokens = true;
        });
        return services;
    }
}