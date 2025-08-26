using FluentAssertions;
using RaylightApi.Domain.Entities;
using RaylightApi.Domain.ValueObjects;

namespace Domain.Tests.Entities;

public class MemberTests
{
    [Fact]
    public void Create_GivenValidReference_ShouldReturnMember()
    {
        // Arrange
        var id = Guid.NewGuid();
        var userName = "test";
        var email = Email.Create("test@email.com").Value;
        var emailConfirmed = true;
        var phoneNumber = "1234567890";
        var phoneNumberConfirmed = true;
        var twoFactorEnabled = true;
        var lockoutEnd = DateTime.UtcNow;
        var lockoutEnabled = false;
        var accessFailedCount = 10;

        // Act
        var member = Member.Create(userName, 
                                     email, 
                                     emailConfirmed, 
                                     phoneNumber, 
                                     phoneNumberConfirmed, 
                                     twoFactorEnabled, 
                                     lockoutEnd, 
                                     lockoutEnabled, 
                                     accessFailedCount, 
                                     id);

        // Assert
        member.UserName.Should().Be(userName);
        member.Email.Should().Be(email);
        member.EmailConfirmed.Should().Be(emailConfirmed);
        member.PhoneNumber.Should().Be(phoneNumber);
        member.PhoneNumberConfirmed.Should().Be(phoneNumberConfirmed);
        member.TwoFactorEnabled.Should().Be(twoFactorEnabled);
        member.LockoutEnd.Should().Be(lockoutEnd);
        member.LockoutEnabled.Should().Be(lockoutEnabled);
        member.AccessFailedCount.Should().Be(accessFailedCount);
        member.Id.Should().Be(id);
    }
}
