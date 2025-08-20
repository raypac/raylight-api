using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Domain.Events;

public sealed record MemberCreatedEvent(Email Email) : IEvent { }