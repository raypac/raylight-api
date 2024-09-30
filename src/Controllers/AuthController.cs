using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;
using raylight.api.Models.Dtos;
using raylight.api.Resources;
using raylight.api.Services;

namespace raylight.api.Controllers
{
    [Route($"{Constants.Api}/[controller]")]
    [ApiController]
    [Authorize]
    public class AuthController : ControllerBase
    {
        private readonly ILogger<AuthController> _logger;
        private readonly IIdentityService _identityService;

        public AuthController(
            IIdentityService identityService,
            ILogger<AuthController> logger)
        {
            _identityService = identityService;
            _logger = logger;
        }

        [AllowAnonymous]
        [HttpPost(Constants.Login)]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest loginRequest)
        {
            if (loginRequest != null)
            {
                var result = await _identityService.Login(loginRequest);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.LoginFailed);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }

        [HttpPost(Constants.Logout)]
        public async Task<IActionResult> Logout([FromBody] RefreshTokenRequest refreshTokenRequest)
        {
            if (refreshTokenRequest != null)
            {
                var result = await _identityService.Logout(refreshTokenRequest);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.RequestInvalid);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }

        [Authorize(Roles = $"{Constants.Verified}")]
        [HttpGet(Constants.Refresh)]
        public async Task<IActionResult> Refresh([FromBody] RefreshTokenRequest refreshTokenRequest)
        {
            if (refreshTokenRequest != null)
            {
                var accessToken = Request.Headers[HeaderNames.Authorization];

                refreshTokenRequest.AccessToken = accessToken.FirstOrDefault()?.Replace(Constants.Bearer, string.Empty)?.Trim();

                var result = await _identityService.Refresh(refreshTokenRequest);

                if (!result.Success)
                {
                    return Forbid(IdentityResources.RefreshFailed);
                }

                return Ok(result);
            }

            return BadRequest(IdentityResources.RequestInvalid);
        }
    }
}
