using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record VerifyMemberPasswordResetCommand(
    string Email, string NewPassword, string Code) : ICommand<bool>;