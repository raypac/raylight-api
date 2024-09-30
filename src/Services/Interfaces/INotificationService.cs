using raylight.api.Enumerations;
using raylight.api.Models.Dtos;

namespace raylight.api.Services
{
    public interface INotificationService
    {
        Task<CommonResult> EmailVerification(string email, string code, UserVerificationType userVerificationType);
    }
}
