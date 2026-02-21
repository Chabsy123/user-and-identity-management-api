using Microsoft.AspNetCore.Identity;
using user_management_data.Models;

namespace user_management_service.Models.Authentication.User
{
    public class CreateUserResponse
    {
        public string Token { get; set; } = null!;

        public ApplicationUser User { get; set; } = null!;
    }
}
