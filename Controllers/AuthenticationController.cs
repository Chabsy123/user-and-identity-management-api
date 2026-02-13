using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using user_and_identity_management_api.Models;
using user_and_identity_management_api.Models.Authentication.SignUp;

namespace user_and_identity_management_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        public AuthenticationController(UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        [HttpPost]
        public async Task<IActionResult> Register ([FromBody] RegisterUser registerUser, string role)
        {
            // Validate email is not null or empty
            if (string.IsNullOrWhiteSpace(registerUser.Email))
            {
                return StatusCode(StatusCodes.Status400BadRequest,
                    new Response{ Status = "Error", Message = "Email cannot be null or empty." });
            }

            //check user exists
            var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExists != null)
            {   
                return StatusCode(StatusCodes.Status403Forbidden, 
                    new Response{ Status = "Error", Message = "User already exists!" });
            }

            // Validate password is not null
            if (string.IsNullOrWhiteSpace(registerUser.Password))
            {
                return StatusCode(StatusCodes.Status400BadRequest,
                    new Response{ Status = "Error", Message = "Password cannot be null or empty." });
            }

            //Add the user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username
            };
            if (await _roleManager.RoleExistsAsync(role))
            {
                var result = await _userManager.CreateAsync(user, registerUser.Password);
                if (!result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });
                }
                //Assign role to the user
                await _userManager.AddToRoleAsync(user, role);
                  return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = "User created successfully!" });
            }
            else
            {
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response
                    {
                        Status = "Error",
                        Message = "Role does not exist."
                    });
            }

            
        }
    }
}
