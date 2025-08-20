using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class MemberLogoutCommandHandler : ICommandHandler<MemberLogoutCommand, bool>
{
    private readonly IMemberIdentityRepository _memberIdentityRepository;

    public MemberLogoutCommandHandler(
        IMemberIdentityRepository memberIdentityRepository)
    {
        _memberIdentityRepository = memberIdentityRepository;
    }
    public async Task<Result<bool>> Handle(MemberLogoutCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.EmailError.Invalid);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.IsFailure)
        {
            return Result.Failure<bool>(memberResult.Error);
        }

        var refreshTokenVerificationResult = await _memberIdentityRepository.RevokeRefreshTokenVerificationAsync(memberResult.Value);

        if (refreshTokenVerificationResult.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        return true;
    }
}