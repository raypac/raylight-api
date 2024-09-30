using Microsoft.AspNetCore.Identity;
using raylight.api.Models.Dtos;

namespace raylight.api.Services
{
    public interface IVerificationService
    {
        Task<CommonResult> SendRegistrationVerification(IdentityUser identityUser, string token);

        Task<CommonResult> SendLoginVerification(IdentityUser identityUser, string token);

        Task<CommonResult> SendPasswordResetVerification(IdentityUser identityUser, string token);

        Task<VerificationResult> ValidateRegistrationCode(VerificationRequest verificationRequest);

        Task<VerificationResult> ValidateLoginCode(VerificationRequest verificationRequest);

        Task<VerificationResult> ValidatePasswordResetCode(VerificationRequest verificationRequest);
    }
}
