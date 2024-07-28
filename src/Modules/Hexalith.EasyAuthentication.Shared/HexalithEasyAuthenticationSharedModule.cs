namespace Hexalith.EasyAuthentication.Shared;

using System.Collections.Generic;
using System.Reflection;

using Hexalith.Application.Modules.Modules;
using Hexalith.EasyAuthentication.Shared.Configurations;
using Hexalith.Extensions.Configuration;
using Hexalith.Extensions.Helpers;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Microsoft Easy Authentication shared module.
/// </summary>
public class HexalithEasyAuthenticationSharedModule : ISharedApplicationModule
{
    /// <inheritdoc/>
    public IEnumerable<string> Dependencies => [];

    /// <inheritdoc/>
    public string Description => "Hexalith Open ID connect shared module";

    /// <inheritdoc/>
    public string Id => "Hexalith.EasyAuthentication.Shared";

    /// <inheritdoc/>
    public string Name => "Hexalith EasyAuthentication shared";

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

        _ = services
            .AddAuthorizationCore()
            .AddCascadingAuthenticationState()
            .ConfigureSettings<EasyAuthenticationSettings>(configuration);
    }

    /// <inheritdoc/>
    public void UseModule(object builder)
    {
    }
}