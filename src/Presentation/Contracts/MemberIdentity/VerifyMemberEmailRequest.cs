namespace RaylightApi.Presentation.Contracts.MemberIdentity;

public sealed record VerifyMemberEmailRequest(string Email, string Code);