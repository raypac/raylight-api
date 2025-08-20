using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.ValueObjects;
using System.Security.Claims;

namespace RaylightApi.Application.Abstractions.Persistence;

public interface IMemberIdentityRepository
{
    Task<Result<bool>> CreateAsync(Email email, Password password);

    Task<Result<Member>> FindByEmailAsync(Email email);

    Task<Result<bool>> AddToRoleAsync(Email email, string role);

    Task<Result<bool>> AddClaimsAsync(Email email, IEnumerable<MemberClaim> claims);

    Task<Result<string>> CreateEmailVerificationAsync(Email email, MemberVerificationType memberVerificationType);

    Task<Result<bool>> VerifyEmailAsync(Email email, string code, MemberVerificationType memberVerificationType);

    Task<Result<bool>> CanSignInAsync(Email email);

    Task<Result<bool>> LoginAsync(Email email, Password password);

    Task<Result<bool>> ChangePasswordAsync(Email email, Password password, Password newPassword);

    Task<Result<bool>> ResetPasswordAsync(Email email, Password newPassword);

    Task<Result<bool>> CreateRefreshTokenVerificationAsync(Email email, Token token);

    Task<Result<bool>> UpdateRefreshTokenVerificationAsync(Member member, Token token);

    Task<Result<RefreshTokenVerification>> GetRefreshTokenVerificationAsync(Member member);

    Task<Result<bool>> RevokeRefreshTokenVerificationAsync(Member member);
}