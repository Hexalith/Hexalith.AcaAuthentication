namespace Hexalith.AzureContainerAppAuthentication.Shared;

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
    public static UserInfo FromClaimsPrincipal(ClaimsPrincipal principal) =>
        new()
        {
            UserId = GetRequiredClaim(principal, UserIdClaimType),
            Name = GetRequiredClaim(principal, NameClaimType),
        };

    /// <summary>
    /// Converts the <see cref="UserInfo"/> instance to a <see cref="ClaimsPrincipal"/>.
    /// </summary>
    /// <returns>A <see cref="ClaimsPrincipal"/> representing the <see cref="UserInfo"/> instance.</returns>
    public ClaimsPrincipal ToClaimsPrincipal() =>
        new(new ClaimsIdentity(
            new[] { new Claim(UserIdClaimType, UserId), new Claim(NameClaimType, Name) },
            authenticationType: nameof(UserInfo),
            nameType: NameClaimType,
            roleType: null));

    private static string GetRequiredClaim(ClaimsPrincipal principal, string claimType) =>
        principal.FindFirst(claimType)?.Value ?? throw new InvalidOperationException($"Could not find required '{claimType}' claim.");
}