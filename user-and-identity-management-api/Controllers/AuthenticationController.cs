using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.ComponentModel.DataAnnotations;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using user_and_identity_management_api.Models;
using user_and_identity_management_api.Models.Authentication.SignUp;
using user_management_service.Models;
using user_management_service.Models.Authentication.Login;
using user_management_service.Models.Authentication.SignUp;
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
        private readonly IUserManagement _user;
        public AuthenticationController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager,IUserManagement user, IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _user = user;
            _configuration = configuration;
            _emailService = emailService;
        }

        [HttpPost]
        public async Task<IActionResult> Register([FromBody] user_management_service.Models.Authentication.SignUp.RegisterUser registerUser)
        {
            var tokenResponse = await _user.CreateUserWithTokenAsync(registerUser);
            if (tokenResponse.IsSuccess)
            {
                await _user.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                var confirmationLink = Url.Action("ConfirmEmail", "Authentication", new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Email Confirmation Link", confirmationLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"User created successfully! Please check your email to confirm your account." });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { Message = tokenResponse.Message, IsSuccess = false });
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

        [HttpPost]
        [AllowAnonymous]
        [Route("forgot-password")]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var forgetPasswordlink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password Link", forgetPasswordlink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                   new Response { Status = "Success", Message = $"Password Changed request is sent on Email {user.Email}.Please Open your email & click the Link" });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                  new Response { Status = "Error", Message = $"Could not send Link to email, please try again." });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };

            return Ok(new
            {
                model
            });
        }

        [HttpPost]
        [AllowAnonymous]
        [Route("reset-password")]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPassResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!resetPassResult.Succeeded)
                {
                    foreach (var error in resetPassResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }

                return StatusCode(StatusCodes.Status200OK,
                   new Response { Status = "Success", Message = $"Password Changed request is sent on Email {user.Email}.Please Open your email & click the Link" });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                  new Response { Status = "Error", Message = $"Could not send Link to email, please try again." });
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
    
