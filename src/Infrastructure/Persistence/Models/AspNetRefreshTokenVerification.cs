using RaylightApi.Domain.Entities.Enums;
using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace RaylightApi.Infrastructure.Persistence.Models;

public class AspNetRefreshTokenVerification
{
    public Guid Id { get; set; }

    public string UserId { get; set; }

    public string Jti { get; set; }

    public DateTime ExpiryDateOnUtc { get; set; }

    public string CreatedBy { get; set; }

    public DateTime CreatedOnUtc { get; set; }

    public string ModifiedBy { get; set; }

    public DateTime ModifiedOnUtc { get; set; }

    public RefreshTokenState State { get; set; }

    [ForeignKey(nameof(UserId))]
    public IdentityUser User { get; set; }
}
