// <copyright file="HexalithApplicationTest.cs" company="Fiveforty SAS Paris France">
//     Copyright (c) Fiveforty SAS Paris France. All rights reserved.
//     Licensed under the MIT license.
//     See LICENSE file in the project root for full license information.
// </copyright>

namespace Hexalith.AzureContainerAppAuthentication.UnitTests.Modules;

using Hexalith.Application.Modules.Applications;
using Hexalith.AzureContainerAppAuthentication.Client;
using Hexalith.AzureContainerAppAuthentication.Server;
using Hexalith.AzureContainerAppAuthentication.Shared;
using Hexalith.UI.Components.Modules;

public class HexalithApplicationTest
{
    [Fact]
    public void ClientServicesFromModulesShouldBeAdded()
    {
        ServiceCollection services = [];
        Mock<IConfiguration> configurationMock = new(MockBehavior.Strict);

        // Mock the configuration GetSection method
        _ = configurationMock
            .Setup(c => c.GetSection(It.IsAny<string>()))
            .Returns(new Mock<IConfigurationSection>().Object);

        HexalithApplication.AddClientServices(services, configurationMock.Object);

        // Check that the client module services have been added by checking if AuthenticationStateProvider has been added
        _ = services
            .Should()
            .ContainSingle(s => s.ServiceType == typeof(AuthenticationStateProvider));
    }

    [Fact]
    public void HexalithApplicationShouldReturnClientModuleTypes()
    {
        _ = HexalithApplication.Client.ClientModules
            .Should()
            .HaveCount(1);
        _ = HexalithApplication.Client.Modules
            .Should()
            .HaveCount(3);
        _ = HexalithApplication.Client.ClientModules
            .Should()
            .Contain(typeof(HexalithAzureContainerAppAuthenticationClientModule));
        _ = HexalithApplication.Client.Modules
            .Should()
            .Contain(typeof(HexalithAzureContainerAppAuthenticationSharedModule));
        _ = HexalithApplication.Client.Modules
            .Should()
            .Contain(typeof(HexalithAzureContainerAppAuthenticationClientModule));
        _ = HexalithApplication.Client.Modules
            .Should()
            .Contain(typeof(HexalithUIComponentsSharedModule));
    }

    [Fact]
    public void HexalithApplicationShouldReturnServerModuleTypes()
    {
        _ = HexalithApplication.Server.ServerModules
            .Should()
            .HaveCount(1);
        _ = HexalithApplication.Server.Modules
            .Should()
            .HaveCount(3);
        _ = HexalithApplication.Server.ServerModules
            .Should()
            .Contain(typeof(HexalithAzureContainerAppAuthenticationServerModule));
        _ = HexalithApplication.Server.Modules
            .Should()
            .Contain(typeof(HexalithAzureContainerAppAuthenticationSharedModule));
        _ = HexalithApplication.Server.Modules
            .Should()
            .Contain(typeof(HexalithUIComponentsSharedModule));
    }
}