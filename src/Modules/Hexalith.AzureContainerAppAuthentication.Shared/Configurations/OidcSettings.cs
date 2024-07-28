namespace Hexalith.AzureContainerAppAuthentication.Shared.Configurations;

using System.Runtime.Serialization;
using System.Text.Json.Serialization;

using Hexalith.Extensions.Configuration;

/// <summary>
/// The Open Id Connect settings.
/// </summary>
/// <param name="Authority">
/// The Authority url. For exemple Microsoft Entra ID authority is
/// 'https://login.microsoftonline.com/{TENANT ID}/v2.0/'
/// Set the {TENANT ID} placeholder to the Tenant ID.
/// The "common" Authority https://login.microsoftonline.com/common/v2.0/ should be used
/// for multi-tenant apps. You can also use the "common" Authority for
/// single-tenant apps, but it requires a custom IssuerValidator as shown
/// in the comments below.
/// </param>
/// <param name="ClientId">
/// Set the client identifier for the application.
/// </param>
/// <param name="ClientSecret">
/// Set the client secret for the application.
/// </param>
[DataContract]
public record AzureContainerAppAuthenticationSettings(
    [property: DataMember]
    [property:JsonConverter(typeof(JsonStringEnumConverter))]
    AzureContainerAppAuthenticationType AzureContainerAppAuthenticationType,
    [property: DataMember]
    string Tenant,
    [property: DataMember]
    string Authority,
    [property: DataMember]
    string ClientId,
    [property: DataMember]
    string ClientSecret) : ISettings
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AzureContainerAppAuthenticationSettings"/> class.
    /// </summary>
    public AzureContainerAppAuthenticationSettings()
        : this(AzureContainerAppAuthenticationType.AzureContainerAppAuthentication, string.Empty, string.Empty, string.Empty, string.Empty)
    {
    }

    /// <summary>
    /// The name of the configuration.
    /// </summary>
    /// <returns>Settings section name.</returns>
    public static string ConfigurationName() => nameof(Hexalith) + ":" + nameof(AzureContainerAppAuthentication);
}