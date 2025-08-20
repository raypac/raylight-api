using Microsoft.Extensions.DependencyInjection;

namespace RaylightApi.Presentation;

public static class DependencyInjection
{
    public static IServiceCollection AddPresentation(this IServiceCollection services)
    {
        services.AddControllers()
                .AddApplicationPart(AssemblyReference.Assembly);

        return services;
    }
}
