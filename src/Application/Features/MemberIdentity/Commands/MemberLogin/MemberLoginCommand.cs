using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberLoginCommand(
    string Email, string Password) : ICommand<MemberLoginResponse>;