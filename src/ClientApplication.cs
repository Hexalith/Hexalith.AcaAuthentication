namespace Hexalith.AcaAuthentication.Client;

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
        => [typeof(HexalithAcaAuthenticationClientModule)];

    /// <inheritdoc/>
    public override Type SharedApplicationType => typeof(SharedApplication);
}