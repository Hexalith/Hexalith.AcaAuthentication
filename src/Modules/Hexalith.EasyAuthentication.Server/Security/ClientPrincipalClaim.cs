namespace Hexalith.EasyAuthentication.Server.Security;

using System.Text.Json.Serialization;

public record ClientPrincipalClaim(
    [property:JsonPropertyName("typ")]
    string Type,
    [property:JsonPropertyName("val")]
    string Value)
{
}