namespace raylight.api.Models.Dtos
{
    public class PasswordResetRequest : ChangePasswordRequest
    {
        public string Code { get; set; }
    }
}