namespace Hexalith.EasyAuthentication.Server.Helpers;

using System;
using System.Diagnostics.CodeAnalysis;

using Hexalith.EasyAuthentication.Server.Security;

using Microsoft.AspNetCore.Authentication;

/// <summary>
/// Provides extension methods for the <see cref="AuthenticationBuilder"/> class.
/// </summary>
public static class EasyAuthenticationBuilder
{
    private const string _easyAuthScheme = "EasyAuth";

    /// <summary>
    /// Adds the EasyAuthentication scheme to the authentication builder.
    /// </summary>
    /// <param name="builder">The authentication builder.</param>
    /// <param name="configure">An action to configure the EasyAuthentication scheme options.</param>
    /// <returns>The authentication builder instance.</returns>
    public static AuthenticationBuilder AddEasyAuthentication(
        [NotNull] this AuthenticationBuilder builder,
        Action<EasyAuthenticationSchemeOptions> configure)
    {
        ArgumentNullException.ThrowIfNull(builder);
        return builder.AddScheme<EasyAuthenticationSchemeOptions, EasyAuthenticationHandler>(
                _easyAuthScheme,
                _easyAuthScheme,
                configure);
    }
}