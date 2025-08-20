namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberLoginResponse(string Token, string RefreshToken, DateTime ExpiryOnUtc);