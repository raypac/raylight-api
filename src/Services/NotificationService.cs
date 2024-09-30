using raylight.api.Enumerations;
using raylight.api.Models.Dtos;

namespace raylight.api.Services
{
    public class NotificationService : INotificationService
    {
        public Task<CommonResult> EmailVerification(string email, string code, UserVerificationType userVerificationType)
        {
            var result = new CommonResult() { Success = true };
            return Task.FromResult(result);
        }
    }
}
