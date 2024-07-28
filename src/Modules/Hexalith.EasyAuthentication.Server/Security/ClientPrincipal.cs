namespace Hexalith.EasyAuthentication.Server.Security;

using System.Collections.Generic;
using System.Runtime.Serialization;
using System.Text.Json.Serialization;

[DataContract]
public record ClientPrincipal(
    [property:JsonPropertyName("auth_typ")]
    string IdentityProvider,
    [property:JsonPropertyName("name_typ")]
    string NameClaimType,
    [property:JsonPropertyName("role_typ")]
    string RoleClaimType,
    [property:JsonPropertyName("claims")]
    IEnumerable<ClientPrincipalClaim> Claims)
{
}