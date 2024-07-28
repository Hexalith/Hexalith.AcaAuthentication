namespace Hexalith.AcaAuthentication.UnitTests.Configurations;

using System.Text.Json;

using FluentAssertions;

using Hexalith.Extensions.Helpers;
using Hexalith.AcaAuthentication.Shared.Configurations;
using Hexalith.TestMocks;

using Microsoft.Extensions.Configuration;

public class AcaAuthenticationSettingsTest : SerializationTestBase
{
    public static Dictionary<string, string> TestSettings => new()
        {
            { "Hexalith:AcaAuthentication:AcaAuthenticationType", "MicrosoftEntraId" },
            { "Hexalith:AcaAuthentication:Tenant", "fiveforty.fr" },
            { "Hexalith:AcaAuthentication:Authority", "https://myauthority" },
            { "Hexalith:AcaAuthentication:ClientId", "125642" },
            { "Hexalith:AcaAuthentication:ClientSecret", "65125642" },
        };

    [Fact]
    public void GetSettingsFromConfigurationShouldSucceed()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(AcaAuthenticationSettingsTest.TestSettings)
            .Build();
        AcaAuthenticationSettings settings = configuration.GetSettings<AcaAuthenticationSettings>();
        _ = settings.Should().NotBeNull();
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://myauthority");
        _ = settings.ClientId.Should().Be("125642");
        _ = settings.ClientSecret.Should().Be("65125642");
        _ = settings.AcaAuthenticationType.Should().Be(AcaAuthenticationType.MicrosoftEntraId);
    }

    [Fact]
    public void ShouldDeserialize()
    {
        // Arrange
        string json = @"{
            ""AcaAuthenticationType"": ""MicrosoftEntraId"",
            ""Tenant"": ""fiveforty.fr"",
            ""Authority"": ""https://helloAcaAuthentication"",
            ""ClientId"": ""123456"",
            ""ClientSecret"": ""789000""
        }";

        // Act
        AcaAuthenticationSettings settings = JsonSerializer.Deserialize<AcaAuthenticationSettings>(json);

        // Assert
        _ = settings.Should().NotBeNull();
        _ = settings.AcaAuthenticationType.Should().Be(AcaAuthenticationType.MicrosoftEntraId);
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://helloAcaAuthentication");
        _ = settings.ClientId.Should().Be("123456");
        _ = settings.ClientSecret.Should().Be("789000");
    }

    public override object ToSerializeObject() => new AcaAuthenticationSettings
    {
        AcaAuthenticationType = AcaAuthenticationType.MicrosoftEntraId,
        Tenant = "fiveforty.fr",
        Authority = "https://helloAcaAuthentication",
        ClientId = "123456",
        ClientSecret = "789000",
    };
}