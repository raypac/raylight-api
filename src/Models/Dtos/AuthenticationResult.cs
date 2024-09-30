namespace raylight.api.Models.Dtos
{
    public class AuthenticationResult
    {
        public string Token { get; set; }

        public string RefreshToken { get; set; }

        public DateTime Expiry { get; set; }

        public bool Success { get; set; }

        public List<string> Errors { get; set; } = new List<string>();
    }
}