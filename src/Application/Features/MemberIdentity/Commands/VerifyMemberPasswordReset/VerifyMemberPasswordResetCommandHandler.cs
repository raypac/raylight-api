using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class VerifyMemberPasswordResetCommandHandler : ICommandHandler<VerifyMemberPasswordResetCommand, VerifyMemberPasswordResetResponse>
{
    private readonly IMemberIdentityRepository _memberIdentityRepository;
    private readonly IJwtService _jwtService;

    public VerifyMemberPasswordResetCommandHandler(
        IMemberIdentityRepository memberIdentityRepository,
        IJwtService jwtService)
    {
        _memberIdentityRepository = memberIdentityRepository;
        _jwtService = jwtService;
    }

    public async Task<Result<VerifyMemberPasswordResetResponse>> Handle(VerifyMemberPasswordResetCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.EmailError.Invalid);
        }

        var newPassword = Password.Create(request.NewPassword);

        if (newPassword.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.PasswordError.Invalid);
        }

        var verifyEmailResult = await _memberIdentityRepository.VerifyEmailAsync(email.Value, request.Code, MemberVerificationType.PasswordReset);

        if (verifyEmailResult.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.MemberIdentityError.ChangePasswordFailed);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.Value != null)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var canSignInResult = await _memberIdentityRepository.CanSignInAsync(email.Value);

        if (canSignInResult.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.LoginError.CantLogin);
        }

        var changePasswordResult = await _memberIdentityRepository.ResetPasswordAsync(email.Value, newPassword.Value);

        if (changePasswordResult.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.MemberIdentityError.ChangePasswordFailed);
        }

        var loginResult = await _memberIdentityRepository.LoginAsync(email.Value, newPassword.Value);

        if (loginResult.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(loginResult.Error);
        }

        var tokenResult = await _jwtService.GenerateToken(email.Value);

        if (tokenResult.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.LoginError.Invalid);
        }

        var updateRefreshTokenResult = await _memberIdentityRepository.UpdateRefreshTokenVerificationAsync(memberResult.Value, tokenResult.Value);

        if (updateRefreshTokenResult.IsFailure)
        {
            return Result.Failure<VerifyMemberPasswordResetResponse>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        return new VerifyMemberPasswordResetResponse(tokenResult.Value.Jwt, tokenResult.Value.RefreshToken, tokenResult.Value.ExpiryDateOnUtc);
    }
}