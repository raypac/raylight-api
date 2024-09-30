using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using raylight.api.Models.Dtos;
using raylight.api.Resources;
using raylight.api.Services;
using System.Security.Claims;

namespace raylight.api.Controllers
{
    [Route($"{Constants.Api}/[controller]")]
    [ApiController]
    [Authorize]
    public class UserController : ControllerBase
    {
        private readonly IIdentityService _identityService;
        private readonly ILogger<AuthController> _logger;

        public UserController(
            IIdentityService identityService,
            ILogger<AuthController> logger)
        {
            _identityService = identityService;
            _logger = logger;
        }

        [AllowAnonymous]
        [HttpPost(Constants.Register)]
        public async Task<IActionResult> Register([FromBody] UserRegistration userRegistration)
        {
            if (userRegistration != null)
            {
                var result = await _identityService.Register(userRegistration);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.RegistrationError);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }

        [HttpPost(Constants.VerifyRegistration)]
        public async Task<IActionResult> VerifyRegistration([FromBody] VerificationRequest verificationRequest)
        {
            if (verificationRequest != null)
            {
                var result = await _identityService.VerifyRegistration(verificationRequest);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.InvalidVerificationCode);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }

        [HttpPost(Constants.PasswordReset)]
        public async Task<IActionResult> PasswordReset([FromBody] PasswordResetRequest passwordResetRequest)
        {
            if (passwordResetRequest != null)
            {
                var result = await _identityService.PasswordReset(passwordResetRequest);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.InvalidVerificationCode);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }

        [HttpPost(Constants.PasswordResetVerification)]
        public async Task<IActionResult> PasswordResetVerification([FromBody] PasswordResetRequest passwordResetRequest)
        {
            if (passwordResetRequest != null)
            {
                var result = await _identityService.PasswordResetVerification(passwordResetRequest);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.InvalidVerificationCode);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }

        [HttpPost(Constants.ChangePassword)]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest changePasswordRequest)
        {
            if (changePasswordRequest != null)
            {
                var result = await _identityService.ChangePassword(changePasswordRequest);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.RequestInvalid);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }

        [HttpGet(Constants.WhoIAm)]
        public async Task<IActionResult> WhoIAm()
        {
            var user = HttpContext.User;

            if (user != null)
            {
                var email = user.Claims
                    .FirstOrDefault(x => x.Type == ClaimTypes.Email).Value;

                return Ok(email);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }
    }
}
