namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record VerifyMemberPasswordResetResponse(string Token, string RefreshToken, DateTime ExpiryOnUtc);