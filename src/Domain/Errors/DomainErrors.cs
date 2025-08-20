using RaylightApi.Domain.Common;

namespace RaylightApi.Domain.Errors;

public static class DomainErrors
{
    public static class EmailError
    {
        public static readonly Error Empty = new(
            "Email.Empty",
            "Email value must not be empty");

        public static readonly Error Invalid = new(
            "Email.InvalidEmail",
            "Email value is invalid");
    }

    public static class PasswordError
    {
        public static readonly Error Empty = new(
            "Password.Empty",
            "Password value must not be empty");

        public static readonly Error Invalid = new(
            "Password.InvalidPassword",
            "Password is not valid");
    }

    public static class MemberIdentityError
    {
        public static readonly Error EmailExist = new(
            "RaylightApi.EmailExist",
            "MemberIdentity email already exist");

        public static readonly Error MemberNotFound = new(
            "RaylightApi.MemberNotFound",
            "MemberIdentity not found");

        public static readonly Error CreateFailed = new(
            "RaylightApi.CreateFailed",
            "MemberIdentity not created");

        public static readonly Error AddToRoleFailed = new(
            "RaylightApi.AddToRoleFailed",
            "MemberIdentity not added to role");

        public static readonly Error AddToClaimFailed = new(
            "RaylightApi.AddToClaimFailed",
            "MemberIdentity not added to claims");

        public static readonly Error EmailVerificationFailed = new(
            "RaylightApi.EmailVerificationFailed",
            "MemberIdentity email verification failed");

        public static readonly Error ChangePasswordFailed = new(
            "RaylightApi.ChangePasswordFailed",
            "MemberIdentity change password failed");


    }

    public static class LoginError
    {
        public static readonly Error Invalid = new(
            "LoginError.Invalid",
            "Login is not valid");

        public static readonly Error CantLogin = new(
            "LoginError.CantSignIn",
            "Member cannot login");
    }

    public static class TokenError
    {
        public static readonly Error Invalid = new(
            "Token.Invalid",
            "Token value is invalid");

        public static readonly Error InvalidAlgorithm = new(
            "Token.InvalidAlgorithm",
            "Token algorithm is invalid");

        public static readonly Error Expired = new(
            "Token.Expired",
            "Token is Expired");

        public static readonly Error Revoked = new(
            "Token.Revoked",
            "Token is Revoked");

        public static readonly Error InvalidClaims = new(
            "Token.InvalidClaims",
            "Token claims is invalid");

        public static readonly Error InvalidEmailClaim = new(
            "Token.InvalidEmailClaim",
            "Token email claim is invalid");

        public static readonly Error InvalidJtiClaim = new(
            "Token.InvalidJtiClaim",
            "Token Jti claim is invalid");

        public static readonly Error TokenVerificationFailed = new(
            "Token.TokenVerificationFailed",
            "Token verification failed");
    }

}