namespace Hexalith.EasyAuthentication.Client;

using System.Collections.Generic;
using System.Reflection;

using Hexalith.Application.Modules.Modules;
using Hexalith.EasyAuthentication.Shared.Configurations;
using Hexalith.Extensions.Helpers;

using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.Extensions.Configuration;

using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Microsoft Easy Authentication client module.
/// </summary>
public class HexalithEasyAuthenticationClientModule : IClientApplicationModule
{
    /// <inheritdoc/>
    public IEnumerable<string> Dependencies => [];

    /// <inheritdoc/>
    public string Description => "Microsoft Easy Authentication client module";

    /// <inheritdoc/>
    public string Id => "Hexalith.EasyAuthentication.Client";

    /// <inheritdoc/>
    public string Name => "Microsoft Easy Authentication client";

    /// <inheritdoc/>
    public int OrderWeight => 0;

    /// <inheritdoc/>
    public string Path => "Hexalith/EasyAuthentication";

    /// <inheritdoc/>
    public IEnumerable<Assembly> PresentationAssemblies => [GetType().Assembly];

    /// <inheritdoc/>
    public string Version => "1.0";

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

        _ = services.AddScoped<AuthenticationStateProvider, ClientPersistentAuthenticationStateProvider>();
    }

    /// <inheritdoc/>
    public void UseModule(object builder)
    {
    }
}