using RaylightApi.Application.Abstractions.Messaging;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

public sealed record MemberLogoutCommand(string Email) : ICommand<bool>;