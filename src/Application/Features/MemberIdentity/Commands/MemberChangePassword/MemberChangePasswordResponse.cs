namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberChangePasswordResponse(string Token, string RefreshToken, DateTime ExpiryOnUtc);