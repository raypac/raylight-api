namespace raylight.api.Models.Dtos
{
    public class VerificationResult
    {
        public string Token { get; set; }

        public bool Success { get; set; }

        public List<string> Errors { get; set; } = new List<string>();
    }
}
