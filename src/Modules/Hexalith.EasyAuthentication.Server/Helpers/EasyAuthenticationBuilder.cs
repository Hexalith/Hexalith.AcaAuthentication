namespace Hexalith.EasyAuthentication.Server.Helpers;

using System;

using Hexalith.EasyAuthentication.Server.Security;

using Microsoft.AspNetCore.Authentication;

public static class EasyAuthenticationBuilder
{
    public static AuthenticationBuilder AddEasyAuthentication(
        this AuthenticationBuilder builder,
        Action<EasyAuthenticationSchemeOptions> configure) =>
            builder.AddScheme<EasyAuthenticationSchemeOptions, EasyAuthAuthenticationHandler>(
                "EasyAuth",
                "EasyAuth",
                configure);
}