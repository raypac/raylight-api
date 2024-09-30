using Microsoft.AspNetCore.Identity;
using raylight.api.Models.Dtos;

namespace raylight.api.Services
{
    public interface IJwtService
    {
        Task<AuthenticationResult> GenerateToken(IdentityUser identityUser, double expiry = Constants.DefaultTokenExpiry);

        Task<AuthenticationResult> RefreshToken(RefreshTokenRequest refreshTokenRequest);
    }
}
