namespace Hexalith.EasyAuthentication.Server;

using System.Collections.Generic;
using System.Reflection;

using Hexalith.Application.Modules.Modules;
using Hexalith.EasyAuthentication.Shared.Configurations;
using Hexalith.Extensions.Helpers;

using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

using NEasyAuthMiddleware;
using NEasyAuthMiddleware.Core;
using NEasyAuthMiddleware.Providers;

/// <summary>
/// Microsoft Easy Authentication server module.
/// </summary>
public sealed class HexalithEasyAuthenticationServerModule : IServerApplicationModule
{
    /// <inheritdoc/>
    public IEnumerable<string> Dependencies => [];

    /// <inheritdoc/>
    public string Description => "Microsoft Easy Authentication server module";

    /// <inheritdoc/>
    public string Id => "Hexalith.EasyAuthentication.Server";

    /// <inheritdoc/>
    public string Name => "Microsoft Easy Authentication server";

    /// <inheritdoc/>
    public int OrderWeight => 0;

    /// <inheritdoc/>
    public IEnumerable<Assembly> PresentationAssemblies => [GetType().Assembly];

    /// <inheritdoc/>
    public string Version => "1.0";

    /// <inheritdoc/>
    string IApplicationModule.Path => HexalithEasyAuthenticationServerModule.Path;

    private static string CookieScheme => "Cookies";

    private static string EasyAuthenticationScheme => "MicrosoftEasyAuthentication";

    private static string Path => "Hexalith/EasyAuthentication";

    /// <summary>
    /// Adds services to the service collection.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configuration">The configuration.</param>
    public static void AddServices(IServiceCollection services, IConfiguration configuration)
    {
        EasyAuthenticationSettings settings = configuration.GetSettings<EasyAuthenticationSettings>()
            ?? throw new InvalidOperationException($"Could not load settings section '{EasyAuthenticationSettings.ConfigurationName()}'");
        if (!settings.Enabled)
        {
            return;
        }

        _ = services
            .AddEasyAuth()
            .AddIdentityCookies();
        _ = services.AddAuthorization();

        // Retrieve the environment name from the environment variable
        string? environmentName = configuration.GetValue<string>("ASPNETCORE_ENVIRONMENT");
        if (environmentName?.Equals("Development", StringComparison.OrdinalIgnoreCase) == true) // Use the mock json file when not running in an app service
        {
            string mockFile = $"{AppDomain.CurrentDomain.BaseDirectory}\\mock_user.json";
            _ = services.AddSingleton((IServiceProvider provider) => new JsonFileHeaderDictionaryProviderOptions
            {
                JsonFilePath = mockFile,
            });
            _ = services.AddSingleton<IHeaderDictionaryProvider, JsonFileHeaderDictionaryProvider>();
        }

        _ = services.AddScoped<AuthenticationStateProvider, ServerPersistingAuthenticationStateProvider>();
    }

    /// <inheritdoc/>
    public void UseModule(object builder)
    {
    }
}