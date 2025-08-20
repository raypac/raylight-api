namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberRefreshTokenResponse(string Token, string RefreshToken, DateTime ExpiryOnUtc);