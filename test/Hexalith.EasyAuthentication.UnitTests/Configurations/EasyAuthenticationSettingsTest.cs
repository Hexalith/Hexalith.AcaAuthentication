namespace Hexalith.EasyAuthentication.UnitTests.Configurations;

using System.Text.Json;

using FluentAssertions;

using Hexalith.EasyAuthentication.Shared.Configurations;
using Hexalith.Extensions.Helpers;
using Hexalith.TestMocks;

using Microsoft.Extensions.Configuration;

public class EasyAuthenticationSettingsTest : SerializationTestBase
{
    public static Dictionary<string, string> TestSettings => new()
        {
            { "Hexalith:EasyAuthentication:Enabled", "true" },
        };

    [Fact]
    public void GetSettingsFromConfigurationShouldSucceed()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(EasyAuthenticationSettingsTest.TestSettings)
            .Build();
        EasyAuthenticationSettings settings = configuration.GetSettings<EasyAuthenticationSettings>();
        _ = settings.Should().NotBeNull();
        _ = settings.Enabled.Should().BeTrue();
    }

    [Fact]
    public void ShouldDeserialize()
    {
        // Arrange
        string json = "{ \"Enabled\": true}";

        // Act
        EasyAuthenticationSettings settings = JsonSerializer.Deserialize<EasyAuthenticationSettings>(json);

        // Assert
        _ = settings.Should().NotBeNull();
        _ = settings.Enabled.Should().BeTrue();
    }

    public override object ToSerializeObject() => new EasyAuthenticationSettings
    {
        Enabled = true,
    };
}