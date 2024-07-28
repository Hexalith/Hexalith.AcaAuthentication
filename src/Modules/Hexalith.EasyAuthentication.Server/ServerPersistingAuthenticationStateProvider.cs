namespace Hexalith.EasyAuthentication.Server;

using Hexalith.EasyAuthentication.Shared;

using Microsoft.AspNetCore.Components;
using Microsoft.AspNetCore.Components.Authorization;
using Microsoft.AspNetCore.Components.Web;

/// <summary>
/// This is a server-side AuthenticationStateProvider that uses PersistentComponentState to flow the
/// authentication state to the client which is then fixed for the lifetime of the WebAssembly application.
/// </summary>
public sealed class ServerPersistingAuthenticationStateProvider :
    AuthenticationStateProvider,
    IHostEnvironmentAuthenticationStateProvider,
    IDisposable
{
    private readonly PersistentComponentState _persistentComponentState;
    private readonly PersistingComponentStateSubscription _subscription;
    private Task<AuthenticationState>? _authenticationStateTask;

    /// <summary>
    /// Initializes a new instance of the <see cref="ServerPersistingAuthenticationStateProvider"/> class.
    /// </summary>
    /// <param name="state">The authentication state.</param>
    public ServerPersistingAuthenticationStateProvider(PersistentComponentState state)
    {
        ArgumentNullException.ThrowIfNull(state);
        _persistentComponentState = state;
        _subscription = state.RegisterOnPersisting(OnPersistingAsync, RenderMode.InteractiveWebAssembly);
    }

    /// <inheritdoc/>
    public void Dispose() => _subscription.Dispose();

    /// <inheritdoc/>
    public override Task<AuthenticationState> GetAuthenticationStateAsync()
        => _authenticationStateTask
            ?? throw new InvalidOperationException(
                $"Do not call {nameof(GetAuthenticationStateAsync)} outside of the DI scope for a Razor component." +
                " Typically, this means you can call it only within a Razor component or inside another DI service that is resolved for a Razor component.");

    /// <inheritdoc/>
    public void SetAuthenticationState(Task<AuthenticationState> authenticationStateTask)
        => _authenticationStateTask = authenticationStateTask;

    private async Task OnPersistingAsync()
    {
        AuthenticationState authenticationState = await GetAuthenticationStateAsync().ConfigureAwait(false);
        System.Security.Claims.ClaimsPrincipal principal = authenticationState.User;

        if (principal.Identity?.IsAuthenticated == true)
        {
            _persistentComponentState.PersistAsJson(nameof(UserInfo), UserInfo.FromClaimsPrincipal(principal));
        }
    }
}