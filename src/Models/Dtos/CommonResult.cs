namespace raylight.api.Models.Dtos
{
    public class CommonResult
    {
        public bool Success { get; set; }

        public List<string> Errors { get; set; } = new List<string>();
    }
}