namespace Hexalith.EasyAuthentication.Client;

using System.Diagnostics.CodeAnalysis;
using System.Security.Claims;

using Hexalith.EasyAuthentication.Shared;

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;

/// <summary>
/// This is a client-side AuthenticationStateProvider that determines the user's authentication state by
/// looking for data persisted in the page when it was rendered on the server. This authentication state will
/// be fixed for the lifetime of the WebAssembly application. So, if the user needs to log in or out, a full
/// page reload is required.
///
/// This only provides a user name and email for display purposes. It does not actually include any tokens
/// that authenticate to the server when making subsequent requests. That works separately using a
/// cookie that will be included on HttpClient requests to the server.
/// </summary>
public sealed class ClientPersistentAuthenticationStateProvider : AuthenticationStateProvider
{
    private static readonly Task<AuthenticationState> _defaultUnauthenticatedTask =
        Task.FromResult(new AuthenticationState(new ClaimsPrincipal(new ClaimsIdentity())));

    private readonly Task<AuthenticationState> _authenticationStateTask = _defaultUnauthenticatedTask;

    /// <summary>
    /// Initializes a new instance of the <see cref="ClientPersistentAuthenticationStateProvider"/> class.
    /// </summary>
    /// <param name="state">The authentication state.</param>
    public ClientPersistentAuthenticationStateProvider(PersistentComponentState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        if (!state.TryTakeFromJson<UserInfo>(nameof(UserInfo), out UserInfo? userInfo) || userInfo is null)
        {
            return;
        }

        _authenticationStateTask = Task.FromResult(new AuthenticationState(userInfo.ToClaimsPrincipal()));
    }

    /// <inheritdoc/>
    [SuppressMessage("Usage", "VSTHRD003:Avoid awaiting foreign Tasks", Justification = "Not applicable here.")]
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
        => _authenticationStateTask;
}