using Microsoft.Extensions.Configuration;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.ValueObjects;
using System.Diagnostics;

namespace RaylightApi.Infrastructure.Services;

internal sealed class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;

    public EmailService(
        IConfiguration configuration)
    {
        _configuration = configuration;
    }

    public async Task SendEmailVerificationAsync(Email email, string code, CancellationToken cancellationToken = default)
    {
        var message = $"SendEmailVerificationAsync:  {email.Value} - {code}";
        Debug.WriteLine(message);
        await SendEmailAsync(email, "Email Verification", message);
    }

    public async Task SendEmailVerifiedAsync(Email email, CancellationToken cancellationToken = default)
    {
        var message = $"SendEmailVerifiedAsync:  {email.Value}";
        Debug.WriteLine(message);
        await SendEmailAsync(email, "Email Verified", message);
    }

    public async Task SendPasswordResetVerificationAsync(Email email, string code, CancellationToken cancellationToken = default)
    {
        var message = $"SendPasswordResetVerificationAsync:  {email.Value} - {code}";
        Debug.WriteLine(message);
        await SendEmailAsync(email, "Password Reset Verification", message);
    }

    private Task<bool> SendEmailAsync(Email email, string subject, string htmlMessage, CancellationToken cancellationToken = default)
    {
        return Task.FromResult(true);
    }
}