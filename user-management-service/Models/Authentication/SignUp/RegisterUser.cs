using System.ComponentModel.DataAnnotations;

namespace user_management_service.Models.Authentication.SignUp
{
    public class RegisterUser
    {
        [Required(ErrorMessage = "User Name is Required")]
        public string? Username { get; set; }

        [EmailAddress]
        [Required(ErrorMessage = "Email is Required")]
        public string? Email { get; set; }

        [Required(ErrorMessage = "Password is Required")]
        public string? Password { get; set; }
        public List<string>? Roles { get; set;  }
    }
}
