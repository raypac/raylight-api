using FluentAssertions;
using NetArchTest.Rules;

namespace Architecture.Test;

public class ArchitectureTest
{
    private const string DomainNamespace = "RaylightApi.Domain";
    private const string ApplicationNamespace = "RaylightApi.Application";
    private const string InfrastructureNamespace = "RaylightApi.Infrastructure";
    private const string PresentationNamespace = "RaylightApi.Presentation";
    private const string WebApiNamespace = "RaylightApi.WebApi";

    [Fact]
    public void Domain_Should_Not_Have_DepedencyOnOtherProject()
    {
        // Arrange
        var assembly = RaylightApi.Domain.AssemblyReference.Assembly;

        var otherProjects = new[]
        {
            ApplicationNamespace,
            InfrastructureNamespace,
            PresentationNamespace,
            WebApiNamespace
        };

        // Act
        var result = Types.InAssembly(assembly)
                          .ShouldNot()
                          .HaveDependencyOnAll(otherProjects)
                          .GetResult();

        // Assert
        result.IsSuccessful.Should().BeTrue();
    }

    [Fact]
    public void Application_Should_Not_Have_DepedencyOnOtherProject()
    {
        // Arrange
        var assembly = RaylightApi.Application.AssemblyReference.Assembly;

        var otherProjects = new[]
        {
            InfrastructureNamespace,
            PresentationNamespace,
            WebApiNamespace
        };

        // Act
        var result = Types.InAssembly(assembly)
                          .ShouldNot()
                          .HaveDependencyOnAll(otherProjects)
                          .GetResult();

        // Assert
        result.IsSuccessful.Should().BeTrue();
    }

    [Fact]
    public void Handlers_Should_Not_Have_DepedencyOnDomain()
    {
        // Arrange
        var assembly = RaylightApi.Application.AssemblyReference.Assembly;


        // Act
        var result = Types.InAssembly(assembly)
                          .That()
                          .HaveNameEndingWith("Handler")
                          .Should()
                          .HaveDependencyOn(DomainNamespace)
                          .GetResult();

        // Assert
        result.IsSuccessful.Should().BeTrue();
    }

    [Fact]
    public void Infrastructure_Should_Not_Have_DepedencyOnOtherProject()
    {
        // Arrange
        var assembly = RaylightApi.Infrastructure.AssemblyReference.Assembly;

        var otherProjects = new[]
        {
            PresentationNamespace,
            WebApiNamespace
        };

        // Act
        var result = Types.InAssembly(assembly)
                          .ShouldNot()
                          .HaveDependencyOnAll(otherProjects)
                          .GetResult();

        // Assert
        result.IsSuccessful.Should().BeTrue();
    }

    [Fact]
    public void Presentation_Should_Not_Have_DepedencyOnOtherProject()
    {
        // Arrange
        var assembly = RaylightApi.Presentation.AssemblyReference.Assembly;

        var otherProjects = new[]
        {
            InfrastructureNamespace,
            WebApiNamespace
        };

        // Act
        var result = Types.InAssembly(assembly)
                          .ShouldNot()
                          .HaveDependencyOnAll(otherProjects)
                          .GetResult();

        // Assert
        result.IsSuccessful.Should().BeTrue();
    }

    [Fact]
    public void Controllers_Should_Not_Have_DepedencyOnMediatR()
    {
        // Arrange
        var assembly = RaylightApi.Infrastructure.AssemblyReference.Assembly;

        var otherProjects = new[]
        {
            InfrastructureNamespace,
            WebApiNamespace
        };

        // Act
        var result = Types.InAssembly(assembly)
                          .That()
                          .HaveNameEndingWith("Controller")
                          .Should()
                          .HaveDependencyOn("MediatR")
                          .GetResult();

        // Assert
        result.IsSuccessful.Should().BeTrue();
    }
}