namespace Hexalith.AcaAuthentication.Client;

using Hexalith.Application.Modules.Applications;
using Hexalith.AcaAuthentication.Shared;
using Hexalith.UI.Components.Modules;

/// <summary>
/// Represents a shared application.
/// </summary>
public class SharedApplication : HexalithSharedApplication
{
    /// <inheritdoc/>
    public override string HomePath => "hexalith";

    /// <inheritdoc/>
    public override string Id => "hexalithAcaAuthentication";

    /// <inheritdoc/>
    public override string LoginPath => "authentication/login";

    /// <inheritdoc/>
    public override string LogoutPath => "authentication/logout";

    /// <inheritdoc/>
    public override string Name => "Hexalith AcaAuthentication";

    /// <inheritdoc/>
    public override IEnumerable<Type> SharedModules =>
    [
        typeof(HexalithAcaAuthenticationSharedModule), typeof(HexalithUIComponentsSharedModule)
    ];
}