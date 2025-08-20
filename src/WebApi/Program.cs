using RaylightApi.Application;
using RaylightApi.Infrastructure;
using RaylightApi.Presentation;
using RaylightApi.WebApi;

var builder = WebApplication.CreateBuilder(args);

builder
    .Services
        .AddApplication()
        .AddInfrastructure(builder.Configuration)
        .AddPresentation()
        .AddWebApi(builder.Configuration);

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();

app.UseAuthorization();

app.UseCors("Open");

app.MapControllers();

app.Run();
