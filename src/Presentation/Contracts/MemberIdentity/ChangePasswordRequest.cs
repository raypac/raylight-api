namespace RaylightApi.Presentation.Contracts.MemberIdentity;

public sealed record ChangePasswordRequest(string Password, string NewPassword);
