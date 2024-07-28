namespace Hexalith.EasyAuthentication.Client;

using Hexalith.EasyAuthentication.Shared;
using Hexalith.Application.Modules.Applications;
using Hexalith.UI.Components.Modules;

/// <summary>
/// Represents a shared application.
/// </summary>
public class SharedApplication : HexalithSharedApplication
{
    /// <inheritdoc/>
    public override string HomePath => "EasyAuthentication";

    /// <inheritdoc/>
    public override string Id => "HexalithEasyAuthentication";

    /// <inheritdoc/>
    public override string LoginPath => ".auth/login";

    /// <inheritdoc/>
    public override string LogoutPath => ".auth/logout";

    /// <inheritdoc/>
    public override string Name => "Hexalith Azure Container App Authentication";

    /// <inheritdoc/>
    public override IEnumerable<Type> SharedModules =>
    [
        typeof(HexalithEasyAuthenticationSharedModule), typeof(HexalithUIComponentsSharedModule)
    ];
}