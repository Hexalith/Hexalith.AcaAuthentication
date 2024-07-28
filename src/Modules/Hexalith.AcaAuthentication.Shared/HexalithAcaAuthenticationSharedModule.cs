namespace Hexalith.AcaAuthentication.Shared;

using System.Collections.Generic;
using System.Reflection;

using Hexalith.Application.Modules.Modules;
using Hexalith.AcaAuthentication.Shared.Configurations;
using Hexalith.Extensions.Configuration;

using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

/// <summary>
/// Microsoft Entra ID shared module.
/// </summary>
public class HexalithAcaAuthenticationSharedModule : ISharedApplicationModule
{
    /// <inheritdoc/>
    public IEnumerable<string> Dependencies => [];

    /// <inheritdoc/>
    public string Description => "Hexalith Open ID connect shared module";

    /// <inheritdoc/>
    public string Id => "Hexalith.AcaAuthentication.Shared";

    /// <inheritdoc/>
    public string Name => "Hexalith AcaAuthentication shared";

    /// <inheritdoc/>
    public int OrderWeight => 0;

    /// <inheritdoc/>
    public string Path => "hexalith/AcaAuthentication";

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
        _ = services
            .AddAuthorizationCore()
            .AddCascadingAuthenticationState()
            .ConfigureSettings<AcaAuthenticationSettings>(configuration);
    }

    /// <inheritdoc/>
    public void UseModule(object builder)
    {
    }
}