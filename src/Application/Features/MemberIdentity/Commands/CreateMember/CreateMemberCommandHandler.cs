using MediatR;
using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.Events;
using RaylightApi.Domain.ValueObjects;
using Microsoft.IdentityModel.JsonWebTokens;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class CreateMemberCommandHandler : ICommandHandler<CreateMemberCommand, Guid>
{
    private readonly IMediator _mediator;
    private readonly IMemberIdentityRepository _memberIdentityRepository;

    public CreateMemberCommandHandler(IMediator mediator,
                                      IMemberIdentityRepository memberIdentityRepository)
    {
        _mediator = mediator;
        _memberIdentityRepository = memberIdentityRepository;
    }

    public async Task<Result<Guid>> Handle(CreateMemberCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);
        var password = Password.Create(request.Password);

        if (email.IsFailure)
        {
            return Result.Failure<Guid>(email.Error);
        }

        if (password.IsFailure)
        {
            return Result.Failure<Guid>(password.Error);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.IsSuccess)
        {
            return Result.Failure<Guid>(DomainErrors.MemberIdentityError.EmailExist);
        }

        var createResult = await _memberIdentityRepository.CreateAsync(email.Value, password.Value);

        if (createResult.IsFailure)
        {
            return Result.Failure<Guid>(DomainErrors.MemberIdentityError.CreateFailed);
        }

        var newMemberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (newMemberResult.IsFailure)
        {
            return Result.Failure<Guid>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var createRoleResult = await _memberIdentityRepository.AddToRoleAsync(newMemberResult.Value.Email, 
                                                                              MemberRoleType.User.ToString());
        if (createRoleResult.IsFailure)
        {
            return Result.Failure<Guid>(DomainErrors.MemberIdentityError.AddToRoleFailed);
        }

        var memberClaims = new List<MemberClaim>()
        {
            MemberClaim.Create(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            MemberClaim.Create(JwtRegisteredClaimNames.Email, newMemberResult.Value.Email.Value)
        };

        var addClaimResult = await _memberIdentityRepository.AddClaimsAsync(newMemberResult.Value.Email, memberClaims);

        if (addClaimResult.IsFailure)
        {
            return Result.Failure<Guid>(DomainErrors.MemberIdentityError.AddToClaimFailed);
        }

        await _mediator.Publish(new MemberCreatedEvent(newMemberResult.Value.Email));

        return newMemberResult.Value.Id;
    }
}