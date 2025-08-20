using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberRefreshTokenCommand(
    string Email, string Jwt, string RefreshToken) : ICommand<MemberRefreshTokenResponse>;