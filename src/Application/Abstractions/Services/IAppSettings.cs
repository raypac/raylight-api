namespace RaylightApi.Application.Abstractions.Services;

public interface IAppSettings
{
    string AppName { get; }
    string AppVersion { get; }

}
