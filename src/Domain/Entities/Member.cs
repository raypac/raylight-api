using RaylightApi.Domain.Primitives;
using RaylightApi.Domain.ValueObjects;

namespace RaylightApi.Domain.Entities;

public sealed class Member : AggregateRoot
{
    private Member()
    {
    }

    internal Member(Guid id,
                    string userName,
                    Email email,
                    bool emailConfirmed,
                    string? phoneNumber,
                    bool phoneNumberConfirmed,
                    bool twoFactorEnabled,
                    DateTimeOffset? lockoutEnd,
                    bool lockoutEnabled,
                    int accessFailedCount) : base(id)
    {
        UserName = userName;
        Email = email;
        EmailConfirmed = emailConfirmed;
        PhoneNumber = phoneNumber;
        PhoneNumberConfirmed = phoneNumberConfirmed;
        TwoFactorEnabled = twoFactorEnabled;
        LockoutEnd = lockoutEnd;
        LockoutEnabled = lockoutEnabled;
        AccessFailedCount = accessFailedCount;
    }

    public string UserName { get; private set; }

    public Email Email { get; private set; }

    public bool EmailConfirmed { get; private set; }

    public string? PhoneNumber { get; private set; }

    public bool PhoneNumberConfirmed { get; private set; }

    public bool TwoFactorEnabled { get; private set; }

    public DateTimeOffset? LockoutEnd { get; private set; }

    public bool LockoutEnabled { get; private set; }

    public int AccessFailedCount { get; private set; }

    public static Member Create(string userName,
                                Email email,
                                bool emailConfirmed,
                                string? phoneNumber,
                                bool phoneNumberConfirmed,
                                bool twoFactorEnabled,
                                DateTimeOffset? lockoutEnd,
                                bool lockoutEnabled,
                                int accessFailedCount,
                                Guid id = default)
    {
        if (id == default)
        {
            id = Guid.NewGuid();
        }

        return new Member(id, 
                          userName, 
                          email, 
                          emailConfirmed, 
                          phoneNumber, 
                          phoneNumberConfirmed, 
                          twoFactorEnabled, 
                          lockoutEnd, 
                          lockoutEnabled, 
                          accessFailedCount);

    }
}