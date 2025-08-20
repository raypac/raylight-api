using MediatR;
using RaylightApi.Domain.Common;

namespace RaylightApi.Application.Abstractions.Messaging;

public interface ICommand : IRequest<Result> 
{ 
}

public interface ICommand<TResponse> 
    : IRequest<Result<TResponse>> 
{ 
}