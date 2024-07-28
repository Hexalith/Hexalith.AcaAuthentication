namespace Hexalith.EasyAuthentication.Server.Security;

using Microsoft.AspNetCore.Authentication;

public class EasyAuthenticationSchemeOptions : AuthenticationSchemeOptions
{
    public EasyAuthenticationSchemeOptions()
    {
        Events = new object();
    }
}