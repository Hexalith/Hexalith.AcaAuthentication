namespace Hexalith.EasyAuthentication.UnitTests.Configurations;

using System.Text.Json;

using FluentAssertions;

using Hexalith.Extensions.Helpers;
using Hexalith.EasyAuthentication.Shared.Configurations;
using Hexalith.TestMocks;

using Microsoft.Extensions.Configuration;

public class EasyAuthenticationSettingsTest : SerializationTestBase
{
    public static Dictionary<string, string> TestSettings => new()
        {
            { "Hexalith:EasyAuthentication:EasyAuthenticationType", "MicrosoftEntraId" },
            { "Hexalith:EasyAuthentication:Tenant", "fiveforty.fr" },
            { "Hexalith:EasyAuthentication:Authority", "https://myauthority" },
            { "Hexalith:EasyAuthentication:ClientId", "125642" },
            { "Hexalith:EasyAuthentication:ClientSecret", "65125642" },
        };

    [Fact]
    public void GetSettingsFromConfigurationShouldSucceed()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(EasyAuthenticationSettingsTest.TestSettings)
            .Build();
        EasyAuthenticationSettings settings = configuration.GetSettings<EasyAuthenticationSettings>();
        _ = settings.Should().NotBeNull();
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://myauthority");
        _ = settings.ClientId.Should().Be("125642");
        _ = settings.ClientSecret.Should().Be("65125642");
        _ = settings.EasyAuthenticationType.Should().Be(EasyAuthenticationType.MicrosoftEntraId);
    }

    [Fact]
    public void ShouldDeserialize()
    {
        // Arrange
        string json = @"{
            ""EasyAuthenticationType"": ""MicrosoftEntraId"",
            ""Tenant"": ""fiveforty.fr"",
            ""Authority"": ""https://helloEasyAuthentication"",
            ""ClientId"": ""123456"",
            ""ClientSecret"": ""789000""
        }";

        // Act
        EasyAuthenticationSettings settings = JsonSerializer.Deserialize<EasyAuthenticationSettings>(json);

        // Assert
        _ = settings.Should().NotBeNull();
        _ = settings.EasyAuthenticationType.Should().Be(EasyAuthenticationType.MicrosoftEntraId);
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://helloEasyAuthentication");
        _ = settings.ClientId.Should().Be("123456");
        _ = settings.ClientSecret.Should().Be("789000");
    }

    public override object ToSerializeObject() => new EasyAuthenticationSettings
    {
        EasyAuthenticationType = EasyAuthenticationType.MicrosoftEntraId,
        Tenant = "fiveforty.fr",
        Authority = "https://helloEasyAuthentication",
        ClientId = "123456",
        ClientSecret = "789000",
    };
}