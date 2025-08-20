using RaylightApi.Domain.Primitives;

namespace RaylightApi.Domain.Entities;

public sealed class MemberClaim : Entity
{
    private MemberClaim()
    {
        
    }

    internal MemberClaim(string type, string value)
    {
        Type = type;
        Value = value;
    }

    public string Type { get; private set; }

    public string Value { get; private set; }

    public static MemberClaim Create(string type, string value)
    {
        return new MemberClaim(type, value);
    }
}
