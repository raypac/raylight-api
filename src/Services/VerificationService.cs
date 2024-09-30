using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using raylight.api.Data;
using raylight.api.Enumerations;
using raylight.api.Helpers;
using raylight.api.Models.Dtos;
using raylight.api.Models.Entities;
using raylight.api.Resources;

namespace raylight.api.Services
{
    public class VerificationService : IVerificationService
    {
        private readonly INotificationService _notificationService;
        private readonly ApplicationDbContext _applicationDbContext;

        public VerificationService(
            INotificationService notificationService,
            ApplicationDbContext applicationDbContext)
        {
            _notificationService = notificationService;
            _applicationDbContext = applicationDbContext;
        }

        public async Task<CommonResult> SendRegistrationVerification(IdentityUser identityUser, string token)
        {
            var result = new CommonResult() { Success = true };

            try
            {
                var code = RandomGenerator.RandomNumeric(Constants.DefaultRandomNumberLength);
                var userVerification =
                    NewAspNetUserVerification(identityUser, code, token, UserVerificationType.Registration);

                await _applicationDbContext.AspNetUserVerifications.AddAsync(userVerification);
                await _applicationDbContext.SaveChangesAsync();
                await _notificationService.EmailVerification(identityUser.Email, code, UserVerificationType.Registration);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<CommonResult> SendLoginVerification(IdentityUser identityUser, string token)
        {
            var result = new CommonResult() { Success = true };

            try
            {
                var code = RandomGenerator.RandomNumeric(Constants.DefaultRandomNumberLength);
                var userVerification =
                    NewAspNetUserVerification(identityUser, code, token, UserVerificationType.Login);

                await _applicationDbContext.AspNetUserVerifications.AddAsync(userVerification);
                await _applicationDbContext.SaveChangesAsync();
                await _notificationService.EmailVerification(identityUser.Email, code, UserVerificationType.PasswordReset);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<CommonResult> SendPasswordResetVerification(IdentityUser identityUser, string token)
        {
            var result = new CommonResult() { Success = true };

            try
            {
                var code = RandomGenerator.RandomNumeric(Constants.DefaultRandomNumberLength);
                var userVerification =
                    NewAspNetUserVerification(identityUser, code, token, UserVerificationType.PasswordReset);

                await _applicationDbContext.AspNetUserVerifications.AddAsync(userVerification);
                await _applicationDbContext.SaveChangesAsync();
                await _notificationService.EmailVerification(identityUser.Email, code, UserVerificationType.PasswordReset);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<VerificationResult> ValidateRegistrationCode(VerificationRequest verificationRequest)
        {
            var result = new VerificationResult() { Success = true };

            try
            {
                var userVerification = await
                    GetValidUserVerification(verificationRequest, UserVerificationType.Registration);

                if (userVerification == null)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                result.Token = userVerification.Token;

                userVerification.Used = true;
                userVerification.ModifiedDate = DateTime.UtcNow;

                _applicationDbContext.AspNetUserVerifications.Update(userVerification);
                await _applicationDbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<VerificationResult> ValidateLoginCode(VerificationRequest verificationRequest)
        {
            var result = new VerificationResult() { Success = true };

            try
            {
                var userVerification = await
                    GetValidUserVerification(verificationRequest, UserVerificationType.Login);

                if (userVerification == null)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                userVerification.Used = true;
                userVerification.ModifiedDate = DateTime.UtcNow;

                _applicationDbContext.AspNetUserVerifications.Update(userVerification);
                await _applicationDbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<VerificationResult> ValidatePasswordResetCode(VerificationRequest verificationRequest)
        {
            var result = new VerificationResult() { Success = true };

            try
            {
                var userVerification = await
                    GetValidUserVerification(verificationRequest, UserVerificationType.PasswordReset);

                if (userVerification == null)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                userVerification.Used = true;
                userVerification.ModifiedDate = DateTime.UtcNow;

                _applicationDbContext.AspNetUserVerifications.Update(userVerification);
                await _applicationDbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        private AspNetUserVerification NewAspNetUserVerification(IdentityUser identityUser, string code, string token, UserVerificationType userVerificationType)
        {
            var dateAdded = DateTime.UtcNow;

            return new AspNetUserVerification()
            {
                Id = Guid.NewGuid().ToString(),
                UserId = identityUser.Id,
                Email = identityUser.Email,
                Code = code,
                Token = token,
                VerificationType = userVerificationType,
                AddedDate = dateAdded,
                ModifiedDate = dateAdded,
                ExpiryDate = dateAdded.AddMinutes(Constants.DefaultEmailVerificationExpiry),
                Used = false,
                User = identityUser
            };
        }

        private async Task<AspNetUserVerification> GetValidUserVerification(VerificationRequest verificationRequest, UserVerificationType userVerificationType)
        {
            var result = await _applicationDbContext.AspNetUserVerifications
                    .FirstOrDefaultAsync(o =>
                        o.Email.ToLower() == verificationRequest.Email.ToLower()
                         && o.Code == verificationRequest.Code
                         && o.VerificationType == userVerificationType
                         && o.Used == false);

            if (DateTime.UtcNow >= result.ExpiryDate.ToUniversalTime())
            {
                return null;
            }

            return result;
        }
    }
}
