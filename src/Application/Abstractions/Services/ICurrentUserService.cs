namespace RaylightApi.Application.Abstractions.Services;

public interface ICurrentUserService
{
    string? UserId { get; }

    string CurrentUser { get; }
}