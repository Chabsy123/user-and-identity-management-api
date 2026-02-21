using System.ComponentModel.DataAnnotations;

namespace user_management_service.Models.Authentication.Login
{
    public class LoginModel
    { 
        [Required(ErrorMessage = "User Name is required.")]
        public string? Username { get; set; }

        [Required(ErrorMessage = "Password is required.")]
        public string? Password { get; set; }
    }
}
