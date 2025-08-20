using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Abstractions.Services;

public interface IEmailService
{
    Task SendEmailVerificationAsync(Email email, string code, CancellationToken cancellationToken = default);
    Task SendEmailVerifiedAsync(Email email, CancellationToken cancellationToken = default);
    Task SendPasswordResetVerificationAsync(Email email, string code, CancellationToken cancellationToken = default);
}