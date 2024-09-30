namespace raylight.api.Models.Dtos
{
    public class ChangePasswordRequest : UserLoginRequest
    {
        public string NewPassword { get; set; }
    }
}