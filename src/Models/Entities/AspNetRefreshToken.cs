using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations.Schema;

namespace raylight.api.Models.Entities
{
    public class AspNetRefreshToken
    {
        public int Id { get; set; }

        public string UserId { get; set; }

        public string Email { get; set; }

        public string RefreshToken { get; set; }

        public string JwtId { get; set; }

        public bool IsRevoked { get; set; }

        public DateTime AddedDate { get; set; }

        public DateTime ModifiedDate { get; set; }

        public DateTime ExpiryDate { get; set; }

        [ForeignKey(nameof(UserId))]
        public IdentityUser User { get; set; }
    }
}
