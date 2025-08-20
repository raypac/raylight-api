using MediatR;
using RaylightApi.Domain.Events;

namespace RaylightApi.Application.Abstractions.Messaging;

public interface IEventHandler<TEvent> : INotificationHandler<TEvent>
    where TEvent : IEvent
{
}