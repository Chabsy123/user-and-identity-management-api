using System.ComponentModel.DataAnnotations;

namespace user_and_identity_management_api.Models.Authentication.SignUp
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
    }
}
