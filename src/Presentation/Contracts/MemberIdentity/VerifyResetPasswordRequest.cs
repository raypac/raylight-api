namespace RaylightApi.Presentation.Contracts.MemberIdentity;

public sealed record VerifyResetPasswordRequest(string Email, string NewPassword, string Code);
