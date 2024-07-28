namespace Hexalith.EasyAuthentication.Client;

using System;
using System.Collections.Generic;

using Hexalith.Application.Modules.Applications;

/// <summary>
/// Represents a client application.
/// </summary>
public class ClientApplication : HexalithClientApplication
{
    /// <inheritdoc/>
    public override IEnumerable<Type> ClientModules
        => [typeof(HexalithEasyAuthenticationClientModule)];

    /// <inheritdoc/>
    public override Type SharedApplicationType => typeof(SharedApplication);
}