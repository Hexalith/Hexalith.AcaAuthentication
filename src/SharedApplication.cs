namespace Hexalith.AzureContainerAppAuthentication.Client;

using Hexalith.Application.Modules.Applications;
using Hexalith.AzureContainerAppAuthentication.Shared;
using Hexalith.UI.Components.Modules;

/// <summary>
/// Represents a shared application.
/// </summary>
public class SharedApplication : HexalithSharedApplication
{
    /// <inheritdoc/>
    public override string HomePath => "hexalith";

    /// <inheritdoc/>
    public override string Id => "hexalithAzureContainerAppAuthentication";

    /// <inheritdoc/>
    public override string LoginPath => "authentication/login";

    /// <inheritdoc/>
    public override string LogoutPath => "authentication/logout";

    /// <inheritdoc/>
    public override string Name => "Hexalith AzureContainerAppAuthentication";

    /// <inheritdoc/>
    public override IEnumerable<Type> SharedModules =>
    [
        typeof(HexalithAzureContainerAppAuthenticationSharedModule), typeof(HexalithUIComponentsSharedModule)
    ];
}