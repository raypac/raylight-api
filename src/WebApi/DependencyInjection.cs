using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Quartz;
using RaylightApi.Infrastructure.BackgroundJobs;
using System.Text;

namespace RaylightApi.WebApi;

public static class DependencyInjection
{
    public static IServiceCollection AddWebApi(this IServiceCollection services, IConfiguration configuration)
    {
        services.Scan(selector => selector
            .FromAssemblies(AssemblyReference.Assembly)
            .AddClasses(false)
            .AsImplementedInterfaces()
            .WithScopedLifetime());

        services.AddHttpContextAccessor();

        services.AddEndpointsApiExplorer();
        services.AddSwaggerGen(options =>
        {
            options.SwaggerDoc(Constant.AppVersion, new OpenApiInfo { Title = Constant.AppName, Version = Constant.AppVersion });
            options.AddSecurityDefinition("BearerAuth", new OpenApiSecurityScheme
            {
                Type = SecuritySchemeType.Http,
                Scheme = JwtBearerDefaults.AuthenticationScheme.ToLowerInvariant(),
                In = ParameterLocation.Header,
                Name = "Authorization",
                BearerFormat = "JWT",
                Description = "JWT Authorization header using the Bearer scheme."
            });

            options.OperationFilter<AuthResponsesOperationFilter>();
        });

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = configuration["Jwt:Issuer"],
            ValidAudience = configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration["Jwt:Key"])),
            ClockSkew = TimeSpan.Zero // remove delay of token when expire
        };

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(options => {
            options.SaveToken = true;
            options.TokenValidationParameters = tokenValidationParameters;
        });

        services.AddCors(options =>
        {
            options.AddPolicy("Open", builder => builder.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod());
        });

        services.AddSingleton(tokenValidationParameters);

        services.AddQuartz(configure =>
        {
            var jobKey = new JobKey(nameof(ProcessTokenExpiryJob));

            configure
                .AddJob<ProcessTokenExpiryJob>(jobKey)
                .AddTrigger(
                    trigger => trigger.ForJob(jobKey)
                                      .WithSimpleSchedule(
                                            schedule =>
                                            schedule.WithIntervalInSeconds(10)
                                                    .RepeatForever()));
        });

        services.AddQuartzHostedService();


        return services;
    }
}