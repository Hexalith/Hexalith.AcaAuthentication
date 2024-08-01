namespace Hexalith.EasyAuthentication.Shared;

using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

/// <summary>
/// Add properties to this class and update the server and client AuthenticationStateProviders
/// to expose more information about the authenticated user to the client.
/// </summary>
public sealed class UserInfo
{
    /// <summary>
    /// Gets the claim type for the user's name.
    /// </summary>
    public static string NameClaimType => "name";

    /// <summary>
    /// Gets the claim type for the user's email.
    /// </summary>
    public static string EmailClaimType => ClaimTypes.Email;

    /// <summary>
    /// Gets the claim type for the user's ID.
    /// </summary>
    public static string UserIdClaimType => "sub";

    /// <summary>
    /// Gets the user's name.
    /// </summary>
    public string? Name { get; init; }

    /// <summary>
    /// Gets the user's ID.
    /// </summary>
    public string? UserId { get; init; }

    /// <summary>
    /// Creates a new <see cref="UserInfo"/> instance from the specified <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <param name="principal">The <see cref="ClaimsPrincipal"/> representing the authenticated user.</param>
    /// <returns>A new <see cref="UserInfo"/> instance.</returns>
    public static UserInfo FromClaimsPrincipal([NotNull] ClaimsPrincipal principal)
    {
        ArgumentNullException.ThrowIfNull(principal);
        return new()
        {
            UserId = GetRequiredUserId(principal),
            Name = GetRequiredName(principal),
        };
    }

    /// <summary>
    /// Converts the <see cref="UserInfo"/> instance to a <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <returns>A <see cref="ClaimsPrincipal"/> representing the <see cref="UserInfo"/> instance.</returns>
    public ClaimsPrincipal ToClaimsPrincipal() =>
        new(new ClaimsIdentity(
            [
                new Claim(UserIdClaimType, UserId ?? string.Empty),
                new Claim(NameClaimType, Name ?? string.Empty),
            ],
            authenticationType: nameof(UserInfo),
            nameType: NameClaimType,
            roleType: null));

    private static string GetRequiredName(ClaimsPrincipal principal)
    {
        if (!string.IsNullOrWhiteSpace(principal.Identity?.Name))
        {
            return principal.Identity.Name;
        }

        string? name = principal.FindFirst(NameClaimType)?.Value;
        if (!string.IsNullOrWhiteSpace(name))
        {
            return name;
        }

        name = principal.FindFirst(ClaimTypes.Name)?.Value;
        if (!string.IsNullOrWhiteSpace(name))
        {
            return name;
        }

        name = principal.FindFirst(ClaimTypes.Surname)?.Value;
        string? givenName = principal.FindFirst(ClaimTypes.GivenName)?.Value;
        if (!string.IsNullOrWhiteSpace(givenName))
        {
            return string.IsNullOrWhiteSpace(name) ? givenName : $"{givenName} {name}";
        }

        name = principal.FindAll(ClaimTypes.Email).Where(p => p.Value.Contains('@')).FirstOrDefault()?.Value;
        return !string.IsNullOrWhiteSpace(name) ? name : throw new InvalidOperationException($"Could not find required name claim.");
    }

    private static string GetRequiredUserId(ClaimsPrincipal principal)
    {
        string? name = principal.FindFirst(NameClaimType)?.Value;
        if (!string.IsNullOrWhiteSpace(name))
        {
            return name;
        }

        name = principal.FindFirst(ClaimTypes.Name)?.Value;
        if (!string.IsNullOrWhiteSpace(name))
        {
            return name;
        }

        name = principal.FindFirst(ClaimTypes.Surname)?.Value;
        string? givenName = principal.FindFirst(ClaimTypes.GivenName)?.Value;
        if (!string.IsNullOrWhiteSpace(givenName))
        {
            return string.IsNullOrWhiteSpace(name) ? givenName : $"{givenName} {name}";
        }

        name = principal.FindAll(ClaimTypes.Email).Where(p => p.Value.Contains('@')).FirstOrDefault()?.Value;
        return !string.IsNullOrWhiteSpace(name) ? name : throw new InvalidOperationException($"Could not find required name claim.");
    }
}