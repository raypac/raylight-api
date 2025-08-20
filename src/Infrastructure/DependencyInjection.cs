using RaylightApi.Application.Common;
using RaylightApi.Infrastructure.Persistence;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace RaylightApi.Infrastructure;

public static class DependencyInjection
{
    public static IServiceCollection AddInfrastructure(this IServiceCollection services, IConfiguration configuration)
    {
        services.Scan(selector => selector
            .FromAssemblies(AssemblyReference.Assembly)
            .AddClasses(false)
            .AsImplementedInterfaces()
            .WithScopedLifetime());

        services.AddDbContext<ApplicationDbContext>(options =>
            options.UseSqlServer(configuration.GetConnectionString("DefaultConnection")));

        services.AddIdentity<IdentityUser, IdentityRole>()
            .AddEntityFrameworkStores<ApplicationDbContext>()
            .AddTokenProvider<DataProtectorTokenProvider<IdentityUser>>(TokenOptions.DefaultProvider);

        //TODO: Move the values in config files
        services.Configure<IdentityOptions>(options =>
        {
            // Default Password settings.
            options.Password.RequireDigit = configuration["IdentityOptions:RequireDigit"].ToBool();
            options.Password.RequireLowercase = configuration["IdentityOptions:RequireLowercase"].ToBool();
            options.Password.RequireNonAlphanumeric = configuration["IdentityOptions:RequireNonAlphanumeric"].ToBool();
            options.Password.RequireUppercase = configuration["IdentityOptions:RequireUppercase"].ToBool();
            options.Password.RequiredLength = configuration["IdentityOptions:RequiredLength"].ToInt();
            options.Password.RequiredUniqueChars = configuration["IdentityOptions:RequiredUniqueChars"].ToInt();

            // Default SignIn settings.
            options.SignIn.RequireConfirmedAccount = configuration["IdentityOptions:RequireConfirmedAccount"].ToBool();
            options.SignIn.RequireConfirmedEmail = configuration["IdentityOptions:RequireConfirmedEmail"].ToBool();
            options.SignIn.RequireConfirmedPhoneNumber = configuration["IdentityOptions:RequireConfirmedPhoneNumber"].ToBool();

            // Default User settings.
            options.User.AllowedUserNameCharacters = configuration["IdentityOptions:AllowedUserNameCharacters"]!.ToString();
            options.User.RequireUniqueEmail = configuration["IdentityOptions:RequireUniqueEmail"].ToBool();
        });

        return services;
    }
}