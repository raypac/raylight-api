using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class MemberChangePasswordCommandHandler : ICommandHandler<MemberChangePasswordCommand, MemberChangePasswordResponse>
{
    private readonly IMemberIdentityRepository _memberIdentityRepository;
    private readonly IJwtService _jwtService;

    public MemberChangePasswordCommandHandler(
        IMemberIdentityRepository memberIdentityRepository,
        IJwtService jwtService)
    {
        _memberIdentityRepository = memberIdentityRepository;
        _jwtService = jwtService;
    }

    public async Task<Result<MemberChangePasswordResponse>> Handle(MemberChangePasswordCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.EmailError.Invalid);
        }

        var password = Password.Create(request.Password);

        if (password.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.PasswordError.Invalid);
        }

        var newPassword = Password.Create(request.NewPassword);

        if (newPassword.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.PasswordError.Invalid);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.Value != null)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var canSignInResult = await _memberIdentityRepository.CanSignInAsync(email.Value);

        if (canSignInResult.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.LoginError.CantLogin);
        }

        var changePasswordResult = await _memberIdentityRepository.ChangePasswordAsync(email.Value, password.Value, newPassword.Value);

        if (changePasswordResult.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.MemberIdentityError.ChangePasswordFailed);
        }

        var loginResult = await _memberIdentityRepository.LoginAsync(email.Value, newPassword.Value);

        if (loginResult.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(loginResult.Error);
        }

        var tokenResult = await _jwtService.GenerateToken(email.Value);

        if (tokenResult.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.LoginError.Invalid);
        }

        var updateRefreshTokenResult = await _memberIdentityRepository.UpdateRefreshTokenVerificationAsync(memberResult.Value, tokenResult.Value);

        if (updateRefreshTokenResult.IsFailure)
        {
            return Result.Failure<MemberChangePasswordResponse>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        return new MemberChangePasswordResponse(tokenResult.Value.Jwt, tokenResult.Value.RefreshToken, tokenResult.Value.ExpiryDateOnUtc);
    }
}