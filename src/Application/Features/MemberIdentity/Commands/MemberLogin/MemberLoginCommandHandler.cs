using RaylightApi.Application.Abstractions.Messaging;
using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Application.Features.RaylightApi.Commands;

internal sealed class MemberLoginCommandHandler : ICommandHandler<MemberLoginCommand, MemberLoginResponse>
{
    private readonly IMemberIdentityRepository _memberIdentityRepository;
    private readonly IJwtService _jwtService;

    public MemberLoginCommandHandler(
        IMemberIdentityRepository memberIdentityRepository,
        IJwtService jwtService)
    {
        _memberIdentityRepository = memberIdentityRepository;
        _jwtService = jwtService;
    }

    public async Task<Result<MemberLoginResponse>> Handle(MemberLoginCommand request, CancellationToken cancellationToken)
    {
        var email = Email.Create(request.Email);

        if (email.IsFailure)
        {
            return Result.Failure<MemberLoginResponse>(DomainErrors.EmailError.Invalid);
        }

        var password = Password.Create(request.Password);

        if (password.IsFailure)
        {
            return Result.Failure<MemberLoginResponse>(DomainErrors.PasswordError.Invalid);
        }

        var memberResult = await _memberIdentityRepository.FindByEmailAsync(email.Value);

        if (memberResult.IsFailure)
        {
            return Result.Failure<MemberLoginResponse>(DomainErrors.LoginError.Invalid);
        }

        var loginResult = await _memberIdentityRepository.LoginAsync(email.Value, password.Value);

        if (loginResult.IsFailure)
        {
            return Result.Failure<MemberLoginResponse>(loginResult.Error);
        }

        var tokenResult = await _jwtService.GenerateToken(email.Value);

        if (tokenResult.IsFailure)
        {
            return Result.Failure<MemberLoginResponse>(DomainErrors.LoginError.Invalid);
        }

        var refreshTokenVerification = await _memberIdentityRepository.CreateRefreshTokenVerificationAsync(email.Value, tokenResult.Value);

        if (refreshTokenVerification.IsFailure)
        {
            return Result.Failure<MemberLoginResponse>(DomainErrors.LoginError.Invalid);
        }

        return new MemberLoginResponse(tokenResult.Value.Jwt, tokenResult.Value.RefreshToken, tokenResult.Value.ExpiryDateOnUtc);
    }
}
