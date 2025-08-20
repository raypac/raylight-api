using RaylightApi.Application.Abstractions.Services;
using RaylightApi.Application.Common;
using RaylightApi.Domain.Common;
using RaylightApi.Domain.Entities;
using RaylightApi.Domain.Errors;
using RaylightApi.Domain.ValueObjects;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace RaylightApi.Infrastructure.Services;

internal sealed class JwtService : IJwtService
{
    private readonly IConfiguration _configuration;
    private readonly TokenValidationParameters _tokenValidationParams;
    private readonly UserManager<IdentityUser> _userManager;

    public JwtService(
        IConfiguration configuration,
        TokenValidationParameters tokenValidationParams,
        UserManager<IdentityUser> userManager)
    {
        _configuration = configuration;
        _tokenValidationParams = tokenValidationParams;
        _userManager = userManager;
    }

    public async Task<Result<Token>> GenerateToken(Email email, double expiry = default)
    {
        if (expiry == default)
        {
            expiry = _configuration["Jwt:DefaultExpiry"].ToDouble();
        }

        var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Key"]);
        var issuer = _configuration["Jwt:Issuer"];
        var audience = _configuration["Jwt:Audience"];
        var addedDateOnUtc = DateTime.UtcNow;
        var expiryDateOnUtc = addedDateOnUtc.AddMinutes(expiry);

        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        var claims = await _userManager.GetClaimsAsync(identityUser);

        var securityTokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = expiryDateOnUtc,
            SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature),
            Issuer = issuer,
            Audience = audience
        };

        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
        var token = jwtSecurityTokenHandler.CreateToken(securityTokenDescriptor);
        var jwtToken = jwtSecurityTokenHandler.WriteToken(token);
        var jti = claims.FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)!.Value;
        var refreshToken = await _userManager.GenerateUserTokenAsync(identityUser, TokenOptions.DefaultProvider, "PasswordlessSignInPurpose");

        return Token.Create(jwtToken, refreshToken, expiryDateOnUtc, Guid.Parse(jti));
    }

    public async Task<Result<bool>> ValidateToken(Email email, string jwt, string refreshToken)
    {
        var jwtSecurityTokenHandler = new JwtSecurityTokenHandler();

        // Validate JWT token format
        var claimsPrincipal = jwtSecurityTokenHandler
            .ValidateToken(jwt, _tokenValidationParams, out var securityToken);

        // Validate Encryption Algorithm
        if (securityToken is JwtSecurityToken jwtSecurityToken)
        {
            var validAlg = jwtSecurityToken.Header.Alg
                            .Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase);

            if (!validAlg)
            {
                return Result.Failure<bool>(DomainErrors.TokenError.InvalidAlgorithm);
            }
        }

        // Validate Token Expiry
        var epochSeconds = long
                            .Parse(claimsPrincipal.Claims
                            .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Exp)!.Value);

        var expiryDate = DateTimeOffset.FromUnixTimeSeconds(epochSeconds);

        if (DateTime.UtcNow >= expiryDate)
        {
            return Result.Failure<bool>(DomainErrors.TokenError.Expired);
        }

        var identityUser = await _userManager.FindByEmailAsync(email.Value);

        var claims = await _userManager.GetClaimsAsync(identityUser);

        if (claims == null)
        {
            return Result.Failure<bool>(DomainErrors.TokenError.InvalidClaims);
        }

        // Validate Token Email Claims
        var emailPrincipal = claimsPrincipal.Claims
                                .FirstOrDefault(x => x.Type == ClaimTypes.Email)!.Value;

        var emailClaim = claims
                            .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Email)!.Value;

        if (emailPrincipal != emailClaim)
        {
            return Result.Failure<bool>(DomainErrors.TokenError.InvalidEmailClaim);
        }

        // Validate Jti
        var jtiPrincipal = claimsPrincipal.Claims
                                .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)!.Value;

        var jtiClaim = claims
                            .FirstOrDefault(x => x.Type == JwtRegisteredClaimNames.Jti)!.Value;

        if (jtiPrincipal != jtiClaim)
        {
            return Result.Failure<bool>(DomainErrors.TokenError.InvalidJtiClaim);
        }

        return true;
    }
}
