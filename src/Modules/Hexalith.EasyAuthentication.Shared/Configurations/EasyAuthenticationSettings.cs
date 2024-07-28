namespace Hexalith.EasyAuthentication.Shared.Configurations;

using System.Runtime.Serialization;

using Hexalith.Extensions.Configuration;

/// <summary>
/// Easy Authentication settings.
/// </summary>
[DataContract]
public record EasyAuthenticationSettings(
    [property: DataMember]
    bool Enabled) : ISettings
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EasyAuthenticationSettings"/> class.
    /// </summary>
    public EasyAuthenticationSettings()
        : this(false)
    {
    }

    /// <summary>
    /// The name of the configuration.
    /// </summary>
    /// <returns>Settings section name.</returns>
    public static string ConfigurationName() => nameof(Hexalith) + ":" + nameof(EasyAuthentication);
}