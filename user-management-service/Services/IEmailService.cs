
using user_management_service.Models;

namespace user_management_service.Services
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
