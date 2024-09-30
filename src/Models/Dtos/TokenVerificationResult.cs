using raylight.api.Models.Entities;

namespace raylight.api.Models.Dtos
{
    public class TokenVerificationResult
    {
        public bool Success { get; set; }

        public List<string> Errors { get; set; } = new List<string>();

        public AspNetRefreshToken StoredToken { get; set; }
    }
}
