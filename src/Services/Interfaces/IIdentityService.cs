using raylight.api.Models.Dtos;

namespace raylight.api.Services
{
    public interface IIdentityService
    {
        Task<AuthenticationResult> Register(UserRegistration userRegistration);

        Task<AuthenticationResult> VerifyRegistration(VerificationRequest verificationRequest);

        Task<AuthenticationResult> Login(UserLoginRequest userLoginRequest);

        Task<AuthenticationResult> LoginVerification(VerificationRequest verificationRequest);

        Task<CommonResult> Logout(RefreshTokenRequest refreshTokenRequest);

        Task<AuthenticationResult> Refresh(RefreshTokenRequest refreshTokenRequest);

        Task<CommonResult> ChangePassword(ChangePasswordRequest changePasswordRequest);

        Task<CommonResult> PasswordReset(PasswordResetRequest passwordResetRequest);

        Task<CommonResult> PasswordResetVerification(PasswordResetRequest passwordResetRequest);
    }
}