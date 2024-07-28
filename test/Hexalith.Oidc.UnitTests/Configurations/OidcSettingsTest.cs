namespace Hexalith.Oidc.UnitTests.Configurations;

using System.Text.Json;

using FluentAssertions;

using Hexalith.Extensions.Helpers;
using Hexalith.Oidc.Shared.Configurations;
using Hexalith.TestMocks;

using Microsoft.Extensions.Configuration;

public class OidcSettingsTest : SerializationTestBase
{
    public static Dictionary<string, string> TestSettings => new()
        {
            { "Hexalith:Oidc:OidcType", "MicrosoftEntraId" },
            { "Hexalith:Oidc:Tenant", "fiveforty.fr" },
            { "Hexalith:Oidc:Authority", "https://myauthority" },
            { "Hexalith:Oidc:ClientId", "125642" },
            { "Hexalith:Oidc:ClientSecret", "65125642" },
        };

    [Fact]
    public void GetSettingsFromConfigurationShouldSucceed()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(OidcSettingsTest.TestSettings)
            .Build();
        OidcSettings settings = configuration.GetSettings<OidcSettings>();
        _ = settings.Should().NotBeNull();
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://myauthority");
        _ = settings.ClientId.Should().Be("125642");
        _ = settings.ClientSecret.Should().Be("65125642");
        _ = settings.OidcType.Should().Be(OidcType.MicrosoftEntraId);
    }

    [Fact]
    public void ShouldDeserialize()
    {
        // Arrange
        string json = @"{
            ""OidcType"": ""MicrosoftEntraId"",
            ""Tenant"": ""fiveforty.fr"",
            ""Authority"": ""https://hellooidc"",
            ""ClientId"": ""123456"",
            ""ClientSecret"": ""789000""
        }";

        // Act
        OidcSettings settings = JsonSerializer.Deserialize<OidcSettings>(json);

        // Assert
        _ = settings.Should().NotBeNull();
        _ = settings.OidcType.Should().Be(OidcType.MicrosoftEntraId);
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://hellooidc");
        _ = settings.ClientId.Should().Be("123456");
        _ = settings.ClientSecret.Should().Be("789000");
    }

    public override object ToSerializeObject() => new OidcSettings
    {
        OidcType = OidcType.MicrosoftEntraId,
        Tenant = "fiveforty.fr",
        Authority = "https://hellooidc",
        ClientId = "123456",
        ClientSecret = "789000",
    };
}