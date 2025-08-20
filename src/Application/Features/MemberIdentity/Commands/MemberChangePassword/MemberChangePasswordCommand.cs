using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberChangePasswordCommand(
    string Email, string Password, string NewPassword) : ICommand<MemberChangePasswordResponse>;