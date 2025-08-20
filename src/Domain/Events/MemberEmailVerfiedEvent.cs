using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Domain.Events;

public sealed record MemberEmailVerfiedEvent(Email Email) : IEvent { }