using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record VerifyMemberEmailCommand(
    string Email, string Code) : ICommand<bool>;