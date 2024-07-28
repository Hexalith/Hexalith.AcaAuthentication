namespace Hexalith.AcaAuthentication.Client;

using System;
using System.Collections.Generic;

using Hexalith.Application.Modules.Applications;
using Hexalith.AcaAuthentication.Server;

/// <summary>
/// Represents a server application.
/// </summary>
public class ServerApplication : HexalithServerApplication
{
    /// <inheritdoc/>
    public override Type ClientApplicationType => typeof(ClientApplication);

    /// <inheritdoc/>
    public override IEnumerable<Type> ServerModules => [typeof(HexalithAcaAuthenticationServerModule)];

    /// <inheritdoc/>
    public override Type SharedApplicationType => typeof(SharedApplication);
}