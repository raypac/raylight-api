using MediatR;
using RaylightApi.Domain.Common;

namespace RaylightApi.Application.Abstractions.Messaging;

public interface IQuery<TResponse> : IRequest<Result<TResponse>>
{
}
