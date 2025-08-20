using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberPasswordResetCommand(
    string Email) : ICommand<bool>;