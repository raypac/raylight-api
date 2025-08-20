using MediatR;
using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.Events;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class VerifyMemberEmailHandler : ICommandHandler<VerifyMemberEmailCommand, bool>
{
    private readonly IMediator _mediator;
    private readonly IMemberIdentityRepository _memberIdentityRepository;

    public VerifyMemberEmailHandler(IMediator mediator,
                                      IMemberIdentityRepository memberIdentityRepository)
    {
        _mediator = mediator;
        _memberIdentityRepository = memberIdentityRepository;
    }

    public async Task<Result<bool>> Handle(VerifyMemberEmailCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.EmailVerificationFailed);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.EmailVerificationFailed);
        }

        var verifyEmailResult = await _memberIdentityRepository.VerifyEmailAsync(email.Value, request.Code, MemberVerificationType.EmailConfirmation);

        if (verifyEmailResult.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.EmailVerificationFailed);
        }

        await _mediator.Publish(new MemberEmailVerfiedEvent(memberResult.Value.Email));

        return true;
    }
}