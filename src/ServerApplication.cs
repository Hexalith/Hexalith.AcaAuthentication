namespace Hexalith.EasyAuthentication.Client;

using System;
using System.Collections.Generic;

using Hexalith.Application.Modules.Applications;
using Hexalith.EasyAuthentication.Server;

/// <summary>
/// Represents a server application.
/// </summary>
public class ServerApplication : HexalithServerApplication
{
    /// <inheritdoc/>
    public override Type ClientApplicationType => typeof(ClientApplication);

    /// <inheritdoc/>
    public override IEnumerable<Type> ServerModules => [typeof(HexalithEasyAuthenticationServerModule)];

    /// <inheritdoc/>
    public override Type SharedApplicationType => typeof(SharedApplication);
}