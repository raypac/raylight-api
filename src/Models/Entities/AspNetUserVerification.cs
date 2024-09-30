using Microsoft.AspNetCore.Identity;
using raylight.api.Enumerations;
using System.ComponentModel.DataAnnotations.Schema;

namespace raylight.api.Models.Entities
{
    public class AspNetUserVerification
    {
        public string Id { get; set; }

        public UserVerificationType VerificationType { get; set; }

        public string UserId { get; set; }

        public string Email { get; set; }

        public string Code { get; set; }

        public string Token { get; set; }

        public DateTime AddedDate { get; set; }

        public DateTime ModifiedDate { get; set; }

        public DateTime ExpiryDate { get; set; }

        public bool Used { get; set; } = false;

        [ForeignKey(nameof(UserId))]
        public IdentityUser User { get; set; }
    }
}
