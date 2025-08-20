using MediatR;
using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Events;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class MemberPasswordResetHandler : ICommandHandler<MemberPasswordResetCommand, bool>
{
    private readonly IMediator _mediator;
    private readonly IMemberIdentityRepository _memberIdentityRepository;

    public MemberPasswordResetHandler(IMediator mediator,
                                      IMemberIdentityRepository memberIdentityRepository)
    {
        _mediator = mediator;
        _memberIdentityRepository = memberIdentityRepository;
    }

    public async Task<Result<bool>> Handle(MemberPasswordResetCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<bool>(email.Error);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.IsFailure)
        {
            return Result.Failure<bool>(memberResult.Error);
        }

        await _mediator.Publish(new MemberPasswordResetEvent(memberResult.Value.Email));

        return true;
    }
}