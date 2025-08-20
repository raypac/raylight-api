using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Domain.Events;

public sealed record MemberPasswordResetEvent(Email Email) : IEvent { }