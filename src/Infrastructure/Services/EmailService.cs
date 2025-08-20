using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.ValueObjects;
using System.Diagnostics;

namespace RaylightApi.Infrastructure.Services;

internal sealed class EmailService : IEmailService
{
    public Task SendEmailVerificationAsync(Email email, string code, CancellationToken cancellationToken = default)
    {
        Debug.WriteLine($"SendEmailVerificationAsync:  {email.Value} - {code}");
        return Task.CompletedTask;
    }

    public Task SendEmailVerifiedAsync(Email email, CancellationToken cancellationToken = default)
    {
        Debug.WriteLine($"SendEmailVerifiedAsync:  {email.Value}");
        return Task.CompletedTask;
    }

    public Task SendPasswordResetVerificationAsync(Email email, string code, CancellationToken cancellationToken = default)
    {
        Debug.WriteLine($"SendPasswordResetVerificationAsync:  {email.Value} - {code}");
        return Task.CompletedTask;
    }
}