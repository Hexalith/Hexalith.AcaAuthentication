namespace Hexalith.AzureContainerAppAuthentication.UnitTests.Configurations;

using System.Text.Json;

using FluentAssertions;

using Hexalith.Extensions.Helpers;
using Hexalith.AzureContainerAppAuthentication.Shared.Configurations;
using Hexalith.TestMocks;

using Microsoft.Extensions.Configuration;

public class AzureContainerAppAuthenticationSettingsTest : SerializationTestBase
{
    public static Dictionary<string, string> TestSettings => new()
        {
            { "Hexalith:AzureContainerAppAuthentication:AzureContainerAppAuthenticationType", "MicrosoftEntraId" },
            { "Hexalith:AzureContainerAppAuthentication:Tenant", "fiveforty.fr" },
            { "Hexalith:AzureContainerAppAuthentication:Authority", "https://myauthority" },
            { "Hexalith:AzureContainerAppAuthentication:ClientId", "125642" },
            { "Hexalith:AzureContainerAppAuthentication:ClientSecret", "65125642" },
        };

    [Fact]
    public void GetSettingsFromConfigurationShouldSucceed()
    {
        IConfigurationRoot configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(AzureContainerAppAuthenticationSettingsTest.TestSettings)
            .Build();
        AzureContainerAppAuthenticationSettings settings = configuration.GetSettings<AzureContainerAppAuthenticationSettings>();
        _ = settings.Should().NotBeNull();
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://myauthority");
        _ = settings.ClientId.Should().Be("125642");
        _ = settings.ClientSecret.Should().Be("65125642");
        _ = settings.AzureContainerAppAuthenticationType.Should().Be(AzureContainerAppAuthenticationType.MicrosoftEntraId);
    }

    [Fact]
    public void ShouldDeserialize()
    {
        // Arrange
        string json = @"{
            ""AzureContainerAppAuthenticationType"": ""MicrosoftEntraId"",
            ""Tenant"": ""fiveforty.fr"",
            ""Authority"": ""https://helloAzureContainerAppAuthentication"",
            ""ClientId"": ""123456"",
            ""ClientSecret"": ""789000""
        }";

        // Act
        AzureContainerAppAuthenticationSettings settings = JsonSerializer.Deserialize<AzureContainerAppAuthenticationSettings>(json);

        // Assert
        _ = settings.Should().NotBeNull();
        _ = settings.AzureContainerAppAuthenticationType.Should().Be(AzureContainerAppAuthenticationType.MicrosoftEntraId);
        _ = settings.Tenant.Should().Be("fiveforty.fr");
        _ = settings.Authority.Should().Be("https://helloAzureContainerAppAuthentication");
        _ = settings.ClientId.Should().Be("123456");
        _ = settings.ClientSecret.Should().Be("789000");
    }

    public override object ToSerializeObject() => new AzureContainerAppAuthenticationSettings
    {
        AzureContainerAppAuthenticationType = AzureContainerAppAuthenticationType.MicrosoftEntraId,
        Tenant = "fiveforty.fr",
        Authority = "https://helloAzureContainerAppAuthentication",
        ClientId = "123456",
        ClientSecret = "789000",
    };
}