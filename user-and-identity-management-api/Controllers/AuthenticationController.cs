using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using user_and_identity_management_api.Models;
using user_and_identity_management_api.Models.Authentication.Login;
using user_and_identity_management_api.Models.Authentication.SignUp;
using user_management_service.Models;
using user_management_service.Services;

namespace user_and_identity_management_api.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly IEmailService _emailService;
        public AuthenticationController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser, string role)
        {
            // Validate email is not null or empty
            if (string.IsNullOrWhiteSpace(registerUser.Email))
            {
                return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = "Email cannot be null or empty." });
            }

            //check user exists
            var userExists = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExists != null)
            {
                return StatusCode(StatusCodes.Status403Forbidden,
                    new Response { Status = "Error", Message = "User already exists!" });
            }

            // Validate password is not null
            if (string.IsNullOrWhiteSpace(registerUser.Password))
            {
                return StatusCode(StatusCodes.Status400BadRequest,
                    new Response { Status = "Error", Message = "Password cannot be null or empty." });
            }

            //Add the user in the database
            IdentityUser user = new()
            {
                Email = registerUser.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
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

                //Add Token to verify email
                var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
                var confirmationLink = Url.Action("ConfirmEmail", "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Email Confirmation Link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status201Created,
                    new Response { Status = "Success", Message = $"User created & Email sent to {user.Email} successfully!" });
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

        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);

            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "User not found!" });
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);

            if (result.Succeeded)
            {
                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = "Email confirmed successfully!" });
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Status = "Error", Message = "Email confirmation failed." });
        }

        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            // 1️⃣ Check username and password
            if (string.IsNullOrWhiteSpace(loginModel.Username))
                return BadRequest("Username is required.");

            if (string.IsNullOrWhiteSpace(loginModel.Password))
                return BadRequest("Password is required.");

            // 2️⃣ Find user
            var user = await _userManager.FindByNameAsync(loginModel.Username);

            if (user == null || !await _userManager.CheckPasswordAsync(user, loginModel.Password))
                return Unauthorized("Invalid login attempt");

            // 3️⃣ Generate OTP
            await _signInManager.SignOutAsync();
            await _signInManager.PasswordSignInAsync(user, loginModel.Password, false, true);

            var otpToken = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

            // 4️⃣ Send OTP via email
            var message = new Message(new string[] { user.Email! }, "OTP Confirmation", otpToken!);
            _emailService.SendEmail(message);

            // 5️⃣ Stop here — do NOT generate JWT yet
            return Ok(new Response
            {
                Status = "Success",
                Message = $"OTP sent to your email at {user.Email}"
            });
        }


        [HttpPost("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    var authClaims = new List<Claim>
                    {
                        new Claim(ClaimTypes.Name, user.UserName ?? throw new Exception("Username is null for this user")),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    };
                    var userRoles = await _userManager.GetRolesAsync(user);
                    foreach (var role in userRoles)
                    {
                        authClaims.Add(new Claim(ClaimTypes.Role, role));
                    }

                    var JWTToken = GetToken(authClaims);
                    return Ok(new
                    {
                        token = new JwtSecurityTokenHandler().WriteToken(JWTToken),
                        expiration = JWTToken.ValidTo
                    });
                }
            }
            return StatusCode(StatusCodes.Status404NotFound,
           new Response { Status = "Success", Message = $"Invalid Code" });
        }




        //method to generate the token
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));

            var Token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return Token;

        }
    }
}
    
