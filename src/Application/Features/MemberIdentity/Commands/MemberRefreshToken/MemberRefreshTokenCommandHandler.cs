using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class MemberRefreshTokenCommandHandler : ICommandHandler<MemberRefreshTokenCommand, MemberRefreshTokenResponse>
{
    private readonly IMemberIdentityRepository _memberIdentityRepository;
    private readonly IJwtService _jwtService;

    public MemberRefreshTokenCommandHandler(
        IMemberIdentityRepository memberIdentityRepository,
        IJwtService jwtService)
    {
        _memberIdentityRepository = memberIdentityRepository;
        _jwtService = jwtService;
    }

    public async Task<Result<MemberRefreshTokenResponse>> Handle(MemberRefreshTokenCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<MemberRefreshTokenResponse>(email.Error);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.IsFailure)
        {
            return Result.Failure<MemberRefreshTokenResponse>(memberResult.Error);
        }

        var canSignInResult = await _memberIdentityRepository.CanSignInAsync(email.Value);

        if (canSignInResult.IsFailure)
        {
            return Result.Failure<MemberRefreshTokenResponse>(DomainErrors.LoginError.CantLogin);
        }

        var refreshTokenVerification = await _memberIdentityRepository.GetRefreshTokenVerificationAsync(memberResult.Value);

        if (refreshTokenVerification == null)
        {
            return Result.Failure<MemberRefreshTokenResponse>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        if (refreshTokenVerification.Value.State == RefreshTokenState.Revoked)
        {
            return Result.Failure<MemberRefreshTokenResponse>(DomainErrors.TokenError.Revoked);
        }

        var validateTokenResult = await _jwtService.ValidateToken(memberResult.Value.Email, request.Jwt, request.RefreshToken);

        if (validateTokenResult.IsFailure)
        {
            return Result.Failure<MemberRefreshTokenResponse>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        var tokenResult = await _jwtService.GenerateToken(memberResult.Value.Email);

        if (tokenResult.IsFailure)
        {
            return Result.Failure<MemberRefreshTokenResponse>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        var updateRefreshTokenResult = await _memberIdentityRepository.UpdateRefreshTokenVerificationAsync(memberResult.Value, tokenResult.Value);

        if (updateRefreshTokenResult.IsFailure)
        {
            return Result.Failure<MemberRefreshTokenResponse>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        return new MemberRefreshTokenResponse(tokenResult.Value.Jwt, tokenResult.Value.RefreshToken, tokenResult.Value.ExpiryDateOnUtc);
    }
}
