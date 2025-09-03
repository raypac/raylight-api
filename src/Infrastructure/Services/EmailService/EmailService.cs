using Microsoft.Extensions.Configuration;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.ValueObjects;
using System.Diagnostics;
using System.Net.Http.Json;

namespace RaylightApi.Infrastructure.Services;

internal sealed class EmailService : IEmailService
{
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;

    public EmailService(
        IConfiguration configuration,
        HttpClient httpClient)
    {
        _configuration = configuration;
        _httpClient = httpClient;
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

    private async Task<bool> SendEmailAsync(Email email, string subject, string htmlMessage, CancellationToken cancellationToken = default)
    {
        var endPoint = _configuration["Email:Endpoint"];

        var emailMesage = new EmailMessage()
        {
            Recipients = new List<string> { email.Value },
            Subject = subject,
            Body = htmlMessage,
            IsBodyHtml = true,
        };

        var response = await _httpClient.PostAsJsonAsync(endPoint, emailMesage, cancellationToken);

        response.EnsureSuccessStatusCode();

        return response.IsSuccessStatusCode;
    }
}