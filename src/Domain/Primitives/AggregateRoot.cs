using RaylightApi.Domain.Events;

namespace RaylightApi.Domain.Primitives;

public abstract class AggregateRoot : Entity
{
    private readonly List<IEvent> _domainEvents = new();

    protected AggregateRoot(Guid id)
        : base(id)
    {
    }

    protected AggregateRoot()
    {
    }

    public IReadOnlyCollection<IEvent> GetDomainEvents() => _domainEvents.ToList();

    public void ClearDomainEvents() => _domainEvents.Clear();

    protected void RaiseDomainEvent(IEvent domainEvent) =>
        _domainEvents.Add(domainEvent);
}