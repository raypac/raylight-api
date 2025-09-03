using RaylightApi.Application.Abstractions.Persistence;
using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Application.Common;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities;
using RaylightApi.Domain.Entities.Enums;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;
using RaylightApi.Infrastructure.Persistence.Common;
using RaylightApi.Infrastructure.Persistence.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using System.Security.Claims;

namespace RaylightApi.Infrastructure.Persistence.Repository;

internal sealed class MemberIdentityRepository : IMemberIdentityRepository
{
    private readonly ApplicationDbContext _applicationDbContext;
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly IUnitOfWork _unitOfWork;
    private readonly ICurrentUserService _currentUserService;
    private readonly IConfiguration _configuration;

    public MemberIdentityRepository(ApplicationDbContext applicationDbContext,
                                    SignInManager<IdentityUser> signInManager,
                                    UserManager<IdentityUser> userManager,
                                    IUnitOfWork unitOfWork,
                                    ICurrentUserService currentUserService,
                                    IConfiguration configuration)
    {
        _applicationDbContext = applicationDbContext;
        _signInManager = signInManager;
        _userManager = userManager;
        _unitOfWork = unitOfWork;
        _currentUserService = currentUserService;
        _configuration = configuration;
    }

    public async Task<Result<bool>> CreateAsync(Email email, Password password)
    {
        var identityUser = new IdentityUser()
        {
            UserName = email.Value,
            Email = email.Value
        };

        var result = await _userManager.CreateAsync(identityUser, password.Value);

        return result.Succeeded;
    }

    public async Task<Result<Member>> FindByEmailAsync(Email email)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<Member>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        return Member.Create(identityUser.UserName!,
                             Email.Create(identityUser.Email!).Value,
                             identityUser.EmailConfirmed,
                             identityUser.PhoneNumber,
                             identityUser.PhoneNumberConfirmed,
                             identityUser.TwoFactorEnabled,
                             identityUser.LockoutEnd,
                             identityUser.LockoutEnabled,
                             identityUser.AccessFailedCount,
                             Guid.Parse(identityUser.Id));
    }

    public async Task<Result<bool>> AddToRoleAsync(Email email, string role)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return false;
        }

        var result = await _userManager.AddToRoleAsync(identityUser, role);

        return result.Succeeded;
    }

    public async Task<Result<bool>> AddClaimsAsync(Email email, IEnumerable<MemberClaim> memberClaims)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var claims = memberClaims.Select(x => new Claim(x.Type, x.Value));

        var result = await _userManager.AddClaimsAsync(identityUser, claims);

        return result.Succeeded;
    }

    public async Task<Result<string>> CreateEmailVerificationAsync(Email email, MemberVerificationType memberVerificationType)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<string>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var code = RandomGenerator.RandomNumeric();
        var emailVerificationToken = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
        var currentUser = _currentUserService.UserId;
        var dateAdded = DateTime.UtcNow;

        var memberVerification = new AspNetUserVerification()
        {
            Id = Guid.NewGuid(),
            UserId = identityUser.Id,
            Code = code,
            Token = emailVerificationToken,
            ExpiryDateOnUtc = dateAdded.AddMinutes(_configuration["Members:DefaultEmailVerificationExpiry"].ToDouble()),
            VerificationType = memberVerificationType,
            CreatedBy = currentUser,
            CreatedOnUtc = dateAdded,
            ModifiedBy = currentUser,
            ModifiedOnUtc = dateAdded,
            State = MemberVerificationState.New,
            User = identityUser
        };

        _applicationDbContext.AspNetUserVerifications.Add(memberVerification);
        await _unitOfWork.SaveChangesAsync();

        return code;
    }

    public async Task<Result<bool>> VerifyEmailAsync(Email email, string code, MemberVerificationType memberVerificationType)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var userVerification = _applicationDbContext.AspNetUserVerifications
                                        .Where(x => x.UserId == identityUser.Id &&
                                                    x.VerificationType == memberVerificationType &&
                                                    x.Code == code).FirstOrDefault();

        if (userVerification == null)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.EmailVerificationFailed);
        }

        var result = await _userManager.ConfirmEmailAsync(identityUser, userVerification.Token);

        if (!result.Succeeded)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.EmailVerificationFailed);
        }

        userVerification.State = MemberVerificationState.Completed;
        userVerification.ModifiedBy = _currentUserService.UserId;
        userVerification.ModifiedOnUtc = DateTime.UtcNow;

        _applicationDbContext.AspNetUserVerifications.Update(userVerification);

        await _unitOfWork.SaveChangesAsync();

        return true;
    }

    public async Task<Result<bool>> CanSignInAsync(Email email)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<bool>(DomainErrors.LoginError.CantLogin);
        }

        var canSignIn = await _signInManager.CanSignInAsync(identityUser);

        return canSignIn;
    }

    public async Task<Result<bool>> LoginAsync(Email email, Password password)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<bool>(DomainErrors.LoginError.Invalid);
        }

        var canSignIn = await _signInManager.CanSignInAsync(identityUser);

        if (canSignIn == false)
        {
            return Result.Failure<bool>(DomainErrors.LoginError.CantLogin);
        }

        var signInResult = await _signInManager.CheckPasswordSignInAsync(identityUser, password.Value, true);

        if (!signInResult.Succeeded)
        {
            return Result.Failure<bool>(DomainErrors.LoginError.Invalid);
        }

        return true;
    }

    public async Task<Result<bool>> ChangePasswordAsync(Email email, Password password, Password newPassword)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<bool>(DomainErrors.LoginError.Invalid);
        }

        var changePasswordResult = await _userManager.ChangePasswordAsync(identityUser, password.Value, newPassword.Value);

        if (!changePasswordResult.Succeeded)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.ChangePasswordFailed);
        }

        return true;
    }

    public async Task<Result<bool>> ResetPasswordAsync(Email email, Password newPassword)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<bool>(DomainErrors.LoginError.Invalid);
        }

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(identityUser);

        var resetPasswordResult = await _userManager.ResetPasswordAsync(identityUser, resetToken, newPassword.Value);

        if (!resetPasswordResult.Succeeded)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.ChangePasswordFailed);
        }

        return true;
    }


    public async Task<Result<bool>> CreateRefreshTokenVerificationAsync(Email email, Token token)
    {
        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        if (identityUser == null)
        {
            return Result.Failure<bool>(DomainErrors.MemberIdentityError.MemberNotFound);
        }

        var currentUser = _currentUserService.UserId;
        var dateAdded = DateTime.UtcNow;

        var refreshTokenVerification = await _applicationDbContext.AspNetRefreshTokenVerification
                                            .Where(x => x.UserId == identityUser.Id).FirstOrDefaultAsync();

        if (refreshTokenVerification == null)
        {
            refreshTokenVerification = new AspNetRefreshTokenVerification()
                                            {
                                                Id = Guid.NewGuid(),
                                                Jti = token.Id.ToString(),
                                                ExpiryDateOnUtc = token.ExpiryDateOnUtc,
                                                CreatedBy = currentUser,
                                                CreatedOnUtc = dateAdded,
                                                ModifiedBy = currentUser,
                                                ModifiedOnUtc = dateAdded,
                                                State = RefreshTokenState.Valid,
                                                User = identityUser
                                            };

            _applicationDbContext.AspNetRefreshTokenVerification.Add(refreshTokenVerification);
        }
        else
        {
            refreshTokenVerification.ExpiryDateOnUtc = token.ExpiryDateOnUtc;
            refreshTokenVerification.ModifiedOnUtc = dateAdded;
            refreshTokenVerification.ModifiedBy = currentUser;
            refreshTokenVerification.State = RefreshTokenState.Valid;
            _applicationDbContext.AspNetRefreshTokenVerification.Update(refreshTokenVerification);

        }

        await _unitOfWork.SaveChangesAsync();

        return true;
    }

    public async Task<Result<bool>> UpdateRefreshTokenVerificationAsync(Member member, Token token)
    {
        var currentUser = _currentUserService.UserId;
        var dateAdded = DateTime.UtcNow;

        var refreshTokenVerification = await _applicationDbContext.AspNetRefreshTokenVerification
                                            .Where(x => x.UserId == member.Id.ToString()).FirstOrDefaultAsync();

        if (refreshTokenVerification == null)
        {
            return Result.Failure<bool>(DomainErrors.TokenError.TokenVerificationFailed);
        }
        else
        {
            refreshTokenVerification.ExpiryDateOnUtc = token.ExpiryDateOnUtc;
            refreshTokenVerification.ModifiedOnUtc = dateAdded;
            refreshTokenVerification.ModifiedBy = currentUser;
            refreshTokenVerification.State = RefreshTokenState.Valid;
            _applicationDbContext.AspNetRefreshTokenVerification.Update(refreshTokenVerification);
        }

        await _unitOfWork.SaveChangesAsync();

        return true;
    }

    public async Task<Result<RefreshTokenVerification>> GetRefreshTokenVerificationAsync(Member member)
    {
        var refreshTokenVerification = await _applicationDbContext.AspNetRefreshTokenVerification
                                            .Where(x => x.UserId == member.Id.ToString()).FirstOrDefaultAsync();

        if (refreshTokenVerification == null)
        {
            return Result.Failure<RefreshTokenVerification>(DomainErrors.TokenError.TokenVerificationFailed);
        }

        return RefreshTokenVerification.Create(refreshTokenVerification.UserId, 
                                               refreshTokenVerification.Jti, 
                                               refreshTokenVerification.ExpiryDateOnUtc,
                                               refreshTokenVerification.State,
                                               refreshTokenVerification.Id);
    }

    public async Task<Result<bool>> RevokeRefreshTokenVerificationAsync(Member member)
    {
        var currentUser = _currentUserService.UserId;
        var dateAdded = DateTime.UtcNow;

        var refreshTokenVerification = await _applicationDbContext.AspNetRefreshTokenVerification
                                            .Where(x => x.UserId == member.Id.ToString()).FirstOrDefaultAsync();

        if (refreshTokenVerification == null)
        {
            return Result.Failure<bool>(DomainErrors.TokenError.TokenVerificationFailed);
        }
        else
        {
            refreshTokenVerification.ModifiedOnUtc = dateAdded;
            refreshTokenVerification.ModifiedBy = currentUser;
            refreshTokenVerification.State = RefreshTokenState.Revoked;
            _applicationDbContext.AspNetRefreshTokenVerification.Update(refreshTokenVerification);
        }

        await _unitOfWork.SaveChangesAsync();

        return true;
    }
}