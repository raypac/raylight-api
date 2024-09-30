using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using raylight.api.Data;
using raylight.api.Enumerations;
using raylight.api.Models.Dtos;
using raylight.api.Resources;
using System.Security.Claims;

namespace raylight.api.Services
{
    public class IdentityService : IIdentityService
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly IJwtService _jwtService;
        private readonly IVerificationService _verificationService;
        private readonly ILogger<IdentityService> _logger;

        public IdentityService(SignInManager<IdentityUser> signInManager,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            ApplicationDbContext applicationDbContext,
            IJwtService jwtService,
            IVerificationService verificationService,
            ILogger<IdentityService> logger)
        {
            _signInManager = signInManager;
            _userManager = userManager;
            _roleManager = roleManager;
            _applicationDbContext = applicationDbContext;
            _jwtService = jwtService;
            _verificationService = verificationService;
            _logger = logger;
        }

        public async Task<AuthenticationResult> Register(UserRegistration userRegistration)
        {
            var result = new AuthenticationResult();

            try
            {
                var identityUser = await _userManager.FindByEmailAsync(userRegistration.Email);

                if (identityUser != null)
                {
                    throw new Exception(IdentityResources.UserAlreadyExist);
                }

                identityUser = new IdentityUser()
                {
                    UserName = userRegistration.Email,
                    Email = userRegistration.Email
                };

                var identityResult = await _userManager.CreateAsync(identityUser, userRegistration.Password);

                if (!identityResult.Succeeded)
                {
                    throw new Exception(identityResult.Errors.FirstOrDefault().Description);
                }

                identityUser = await _userManager.FindByEmailAsync(userRegistration.Email);

                if (!identityUser.EmailConfirmed)
                {
                    await _userManager.AddToRoleAsync(identityUser, UserRoleType.Unverified.ToString());
                    var token = await _userManager.GenerateEmailConfirmationTokenAsync(identityUser);
                    await _verificationService.SendRegistrationVerification(identityUser, token);
                }
                else
                {
                    await _userManager.AddToRoleAsync(identityUser, UserRoleType.Verified.ToString()); ;
                }

                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, identityUser.UserName),
                    new Claim(ClaimTypes.Email, identityUser.Email),
                    new Claim(ClaimTypes.Role, UserRoleType.Verified.ToString()),
                };

                await _userManager.AddClaimsAsync(identityUser, claims);

                result = await _jwtService.GenerateToken(identityUser); ;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<AuthenticationResult> VerifyRegistration(VerificationRequest verificationRequest)
        {
            var result = new AuthenticationResult();

            try
            {
                var verificationResult = await _verificationService.ValidateRegistrationCode(verificationRequest);

                if (!verificationResult.Success)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                var identityUser = await _userManager.FindByEmailAsync(verificationRequest.Email);

                if (identityUser == null)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                var identityResult = await _userManager.ConfirmEmailAsync(identityUser, verificationResult.Token);

                if (!identityResult.Succeeded)
                {
                    throw new Exception(identityResult.Errors.FirstOrDefault().Description);
                }

                await _userManager.RemoveFromRoleAsync(identityUser, UserRoleType.Unverified.ToString());
                await _userManager.AddToRoleAsync(identityUser, UserRoleType.Verified.ToString());

                var userClaims = await _userManager.GetClaimsAsync(identityUser);
                await _userManager.RemoveClaimsAsync(identityUser, userClaims);

                var claims = new[]
                {
                    new Claim(ClaimTypes.NameIdentifier, identityUser.UserName),
                    new Claim(ClaimTypes.Email, identityUser.Email),
                    new Claim(ClaimTypes.Role, UserRoleType.Verified.ToString()),
                };

                await _userManager.AddClaimsAsync(identityUser, claims);

                result = await _jwtService.GenerateToken(identityUser); ;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<AuthenticationResult> Login(UserLoginRequest userLoginRequest)
        {
            var result = new AuthenticationResult();

            try
            {
                var identityUser = await _userManager.FindByEmailAsync(userLoginRequest.Email);

                if (identityUser == null)
                {
                    throw new Exception(IdentityResources.InvalidLogin);
                }

                var signInResult = await _signInManager.CheckPasswordSignInAsync(identityUser, userLoginRequest.Password, true);

                if (!signInResult.Succeeded)
                {
                    throw new Exception(IdentityResources.InvalidLogin);
                }

                var canSignIn = await _signInManager.CanSignInAsync(identityUser);

                if (!canSignIn)
                {
                    throw new Exception(IdentityResources.InvalidLogin);
                }

                if (identityUser.TwoFactorEnabled)
                {
                    var token = _userManager.GenerateNewAuthenticatorKey();
                    var commonResult = await _verificationService.SendLoginVerification(identityUser, token);
                    result.Success = commonResult.Success;
                    return result;
                }

                result = await _jwtService.GenerateToken(identityUser); ;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<AuthenticationResult> LoginVerification(VerificationRequest verificationRequest)
        {
            var result = new AuthenticationResult();

            try
            {
                var verificationResult = await _verificationService.ValidateLoginCode(verificationRequest);

                if (verificationResult != null)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                var signinResult = await _signInManager.TwoFactorAuthenticatorSignInAsync(verificationResult.Token, false, false);

                if (!signinResult.Succeeded)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                var identityUser = await _userManager.FindByEmailAsync(verificationRequest.Email);

                var canSignIn = await _signInManager.CanSignInAsync(identityUser);

                if (!canSignIn)
                {
                    throw new Exception(IdentityResources.InvalidLogin);
                }

                result = await _jwtService.GenerateToken(identityUser); ;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<CommonResult> Logout(RefreshTokenRequest refreshTokenRequest)
        {
            var result = new CommonResult() { Success = true };

            try
            {
                var refreshToken = _applicationDbContext.AspNetRefreshTokens.FirstOrDefault(o => o.RefreshToken == refreshTokenRequest.RefreshToken);

                if (refreshToken == null)
                {
                    throw new Exception(IdentityResources.TokenNotFound);
                }

                refreshToken.IsRevoked = true;

                _applicationDbContext.AspNetRefreshTokens.Update(refreshToken);
                await _applicationDbContext.SaveChangesAsync();
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<AuthenticationResult> Refresh(RefreshTokenRequest refreshTokenRequest)
        {
            var result = new AuthenticationResult() { Success = true };

            try
            {
                var refreshToken = await _applicationDbContext.AspNetRefreshTokens
                    .FirstOrDefaultAsync(o => o.RefreshToken == refreshTokenRequest.RefreshToken);

                if (refreshToken == null)
                {
                    throw new Exception(IdentityResources.InvalidToken);
                }

                var identityUser = await _userManager.FindByEmailAsync(refreshToken.Email);

                if (identityUser == null)
                {
                    throw new Exception(IdentityResources.InvalidToken);
                }

                var canSignIn = await _signInManager.CanSignInAsync(identityUser);

                if (!canSignIn)
                {
                    throw new Exception(IdentityResources.InvalidToken);
                }

                result = await _jwtService.RefreshToken(refreshTokenRequest); ;

            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);

            }

            return result;
        }

        public async Task<CommonResult> ChangePassword(ChangePasswordRequest changePasswordRequest)
        {
            var result = new CommonResult() { Success = true };

            try
            {
                var identityUser = await _userManager.FindByEmailAsync(changePasswordRequest.Email);

                if (identityUser == null)
                {
                    throw new Exception(IdentityResources.ChangePasswordFailed);
                }

                var canSignIn = await _signInManager.CanSignInAsync(identityUser);

                if (!canSignIn)
                {
                    throw new Exception(IdentityResources.ChangePasswordFailed);
                }

                var identityResult = await _userManager.ChangePasswordAsync(identityUser,
                    changePasswordRequest.Password, changePasswordRequest.NewPassword);

                if (!identityResult.Succeeded)
                {
                    throw new Exception(IdentityResources.ChangePasswordFailed);
                }

                result.Success = identityResult.Succeeded;
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<CommonResult> PasswordReset(PasswordResetRequest passwordResetRequest)
        {
            var result = new CommonResult() { Success = true };

            try
            {
                var identityUser = await _userManager.FindByEmailAsync(passwordResetRequest.Email);

                if (identityUser == null)
                {
                    throw new Exception(IdentityResources.InvalidUser);
                }

                var canSignIn = await _signInManager.CanSignInAsync(identityUser);

                if (!canSignIn)
                {
                    throw new Exception(IdentityResources.InvalidUser);
                }

                var token = await _userManager.GeneratePasswordResetTokenAsync(identityUser);

                result = await _verificationService.SendPasswordResetVerification(identityUser, token);
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }

        public async Task<CommonResult> PasswordResetVerification(PasswordResetRequest passwordResetRequest)
        {
            var result = new CommonResult();

            try
            {
                var verificationRequest = new VerificationRequest()
                {
                    Code = passwordResetRequest.Code,
                    Email = passwordResetRequest.Email,
                };

                var verificationResult = await _verificationService.ValidatePasswordResetCode(verificationRequest);

                if (verificationResult != null)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                var identityUser = await _userManager.FindByEmailAsync(passwordResetRequest.Email);

                if (identityUser != null)
                {
                    throw new Exception(IdentityResources.InvalidVerificationCode);
                }

                var identityResult = await _userManager.ChangePasswordAsync(identityUser, verificationResult.Token, passwordResetRequest.NewPassword);

                if (!identityResult.Succeeded)
                {
                    throw new Exception(identityResult.Errors.FirstOrDefault().Description);
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors.Add(ex.Message);
            }

            return result;
        }
    }
}
