using MediatR;
using RaylightApi.Domain.Common;

namespace RaylightApi.Application.Abstractions.Messaging;

public interface IQueryHandler<TQuery, TResponse>
    : IRequestHandler<TQuery, Result<TResponse>> where TQuery : IQuery<TResponse>
{
}