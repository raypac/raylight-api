using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Abstractions.Services;

public interface IJwtService
{
    Task<Result<Token>> GenerateToken(Email email, double expiry = default);

    Task<Result<bool>> ValidateToken(Email email, string jwt, string refreshToken);
}
