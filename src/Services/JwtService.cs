using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using raylight.api.Data;
using raylight.api.Helpers;
using raylight.api.Models.Dtos;
using raylight.api.Models.Entities;
using raylight.api.Resources;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace raylight.api.Services
{
    public class JwtService : IJwtService
    {
        private readonly IConfiguration _config;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly ApplicationDbContext _applicationDbContext;
        private readonly TokenValidationParameters _tokenValidationParams;

        public JwtService(IConfiguration config,
            UserManager<IdentityUser> userManager,
            ApplicationDbContext applicationDbContext,
            TokenValidationParameters tokenValidationParams)
        {
            _config = config;
            _userManager = userManager;
            _applicationDbContext = applicationDbContext;
            _tokenValidationParams = tokenValidationParams;
        }

        public async Task<AuthenticationResult> GenerateToken(IdentityUser identityUser, double expiry = Constants.DefaultTokenExpiry)
        {
            var key = Encoding.ASCII.GetBytes(_config["Jwt:Key"]);
            var issuer = _config["Jwt:Issuer"];
            var audience = _config["Jwt:Audience"];
            var addedDate = DateTime.UtcNow;
            var expiryDate = addedDate.AddMinutes(expiry);

            var claims = await _userManager.GetClaimsAsync(identityUser);
            claims.Add(new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()));

            var securityTokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(claims),
                Expires = expiryDate,
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
                Issuer = issuer,
                Audience = audience
            };

            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            var token = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
            var jwtToken = jwtSecurityTokenHandler.WriteToken(token);

            var aspNetRefreshToken = NewAspNetRefreshToken(token.Id, identityUser, addedDate, expiryDate);

            var existingRefreshToken =
                await _applicationDbContext.AspNetRefreshTokens.FirstOrDefaultAsync(o =>
                        o.Email.ToUpper() == identityUser.NormalizedEmail
                        && o.UserId.ToLower() == identityUser.Id.ToLower());

            if (existingRefreshToken != null)
            {
                if (existingRefreshToken.IsRevoked)
                {
                    throw new Exception(IdentityResources.InvalidToken);
                }

                existingRefreshToken.JwtId = token.Id;
                existingRefreshToken.RefreshToken = aspNetRefreshToken.RefreshToken;
                existingRefreshToken.ExpiryDate = aspNetRefreshToken.ExpiryDate;
                existingRefreshToken.ModifiedDate = aspNetRefreshToken.ModifiedDate;
                _applicationDbContext.AspNetRefreshTokens.Update(existingRefreshToken);
                await _applicationDbContext.SaveChangesAsync();
            }
            else
            {
                await _applicationDbContext.AspNetRefreshTokens.AddAsync(aspNetRefreshToken);
                await _applicationDbContext.SaveChangesAsync();
            }

            return new AuthenticationResult()
            {
                Token = jwtToken,
                Success = true,
                Expiry = expiryDate,
                RefreshToken = aspNetRefreshToken.RefreshToken
            };
        }

        private AspNetRefreshToken NewAspNetRefreshToken(string jwtId, IdentityUser identityUser, DateTime addedDate, DateTime expiryDate)
        {
            var aspNetRefreshToken = new AspNetRefreshToken()
            {
                JwtId = jwtId,
                IsRevoked = false,
                UserId = identityUser.Id,
                Email = identityUser.Email,
                AddedDate = addedDate,
                ModifiedDate = addedDate,
                ExpiryDate = expiryDate,
                RefreshToken = RandomGenerator.RandomString(32)
            };

            return aspNetRefreshToken;
        }

        public async Task<AuthenticationResult> RefreshToken(RefreshTokenRequest refreshTokenRequest)
        {
            var tokenVerificationResult = await VerifyToken(refreshTokenRequest);

            if (!tokenVerificationResult.Success)
            {
                return new AuthenticationResult()
                {
                    Errors = tokenVerificationResult.Errors,
                    Success = false
                };
            }

            var identityUser = await _userManager.FindByEmailAsync(tokenVerificationResult.StoredToken.Email);

            var result = await GenerateToken(identityUser);

            return result;
        }

        private async Task<TokenVerificationResult> VerifyToken(RefreshTokenRequest refreshTokenRequest)
        {
            var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

            var result = new TokenVerificationResult() { Success = true };

            try
            {
                // Validate JWT token format
                var claimsPrincipal = jwtSecurityTokenHandler
                    .ValidateToken(refreshTokenRequest.AccessToken, _tokenValidationParams, out var securityToken);

                // Validate Encryption Algorithm
                if (securityToken is JwtSecurityToken jwtSecurityToken)
                {
                    var validAlg = jwtSecurityToken.Header.Alg
                        .Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

                    if (!validAlg)
                    {
                        throw new Exception(IdentityResources.InvalidToken);
                    }
                }

                // Validate Token Expiry
                var epochSeconds = long.Parse(claimsPrincipal.Claims
                    .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp).Value);

                var expiryDate = DateTimeOffset.FromUnixTimeSeconds(epochSeconds);

                if (DateTime.UtcNow >= expiryDate)
                {
                    throw new Exception(IdentityResources.TokenExpired);
                }

                // Validate Token Expiry
                var email = claimsPrincipal.Claims
                    .FirstOrDefault(x => x.Type == ClaimTypes.Email).Value;

                // Validate Token Existence
                result.StoredToken = await _applicationDbContext.AspNetRefreshTokens
                    .FirstOrDefaultAsync(o => o.RefreshToken == refreshTokenRequest.RefreshToken
                        && o.Email.ToLower() == email.ToLower());

                if (result.StoredToken == null)
                {
                    throw new Exception(IdentityResources.TokenNotFound);
                }

                // Validate Token if Revoked
                if (result.StoredToken.IsRevoked)
                {
                    throw new Exception(IdentityResources.TokenRevoked);
                }

                // Validate the Token id
                var jti = claimsPrincipal.Claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti).Value;

                if (result.StoredToken.JwtId != jti)
                {
                    throw new Exception(IdentityResources.TokenNotMatched);
                }
            }
            catch (Exception ex)
            {
                result.Success = false;
                result.Errors = new List<string> { IdentityResources.UnknownError };
                result.StoredToken = null;

                if (ex.Message.Contains($"{IdentityResources.InvalidToken} " +
                    $"{IdentityResources.TokenExpired} " +
                    $"{IdentityResources.TokenNotFound} " +
                    $"{IdentityResources.TokenRevoked} " +
                    $"{IdentityResources.TokenNotMatched}"))
                {
                    result.Errors = new List<string> { ex.Message };
                }

                return result;
            }

            return result;
        }
    }
}
