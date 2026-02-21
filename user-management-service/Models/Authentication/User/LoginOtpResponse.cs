using Microsoft.AspNetCore.Identity;
using user_management_data.Models;

namespace user_management_service.Models.Authentication.User
{
    public class LoginOtpResponse
    {
        public string Token { get; set; } = null!;
        public bool IsTwoFactorEnabled{ get; set; }
        public ApplicationUser User { get; set; } = null!;
    }
}
