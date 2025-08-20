using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record CreateMemberCommand(
    string Email, string Password) : ICommand<Guid>;