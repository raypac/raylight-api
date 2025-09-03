using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class VerifyMemberPasswordResetCommandHandler : ICommandHandler<VerifyMemberPasswordResetCommand, bool>
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

    public async Task<Result<bool>> Handle(VerifyMemberPasswordResetCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.EmailError.Invalid);
        }

        var newPassword = Password.Create(request.NewPassword);

        if (newPassword.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.PasswordError.Invalid);
        }

        var verifyEmailResult = await _memberIdentityRepository.VerifyEmailAsync(email.Value, request.Code, MemberVerificationType.PasswordReset);

        if (verifyEmailResult.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.ChangePasswordFailed);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.Value is null)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var canSignInResult = await _memberIdentityRepository.CanSignInAsync(email.Value);

        if (canSignInResult.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.LoginError.CantLogin);
        }

        var changePasswordResult = await _memberIdentityRepository.ResetPasswordAsync(email.Value, newPassword.Value);

        if (changePasswordResult.IsFailure)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.ChangePasswordFailed);
        }

        return true;
    }
}