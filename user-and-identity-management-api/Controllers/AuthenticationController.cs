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
using user_management_service.Models.Authentication.User;
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

        public AuthenticationController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager, RoleManager<IdentityRole> roleManager, IUserManagement user, IConfiguration configuration, IEmailService emailService)
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

            if (tokenResponse.IsSuccess && tokenResponse.Response != null)
            {
                var createdUser = tokenResponse.Response.User
                    ?? await _userManager.FindByEmailAsync(registerUser.Email!);

                if (createdUser == null)
                {
                    return StatusCode(StatusCodes.Status500InternalServerError,
                        new Response { IsSuccess = false, Message = "User creation failed." });
                }

                // Enable 2FA for the newly created user
                await _userManager.SetTwoFactorEnabledAsync(createdUser, true);

                var roles = registerUser.Roles ?? new List<string>();
                await _user.AssignRoleToUserAsync(roles, createdUser);

                var confirmationLink = $"http://localhost:4200/confirm-account?token={tokenResponse.Response.Token}&email={registerUser.Email ?? string.Empty}";

                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { IsSuccess = true, Message = tokenResponse.Message });
            }

            return StatusCode(StatusCodes.Status500InternalServerError,
                new Response { IsSuccess = false, Message = tokenResponse.Message });
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
            if (string.IsNullOrWhiteSpace(loginModel.Username))
                return BadRequest("Username is required.");

            if (string.IsNullOrWhiteSpace(loginModel.Password))
                return BadRequest("Password is required.");

            var loginOtpResponse = await _user.GetOtpByLoginAsync(loginModel);

            if (!loginOtpResponse.IsSuccess || loginOtpResponse.Response == null)
            {
                return Unauthorized(new Response
                {
                    IsSuccess = false,
                    Status = "Error",
                    Message = loginOtpResponse.Message ?? "Invalid username or password."
                });
            }

            var user = loginOtpResponse.Response.User;

            // Use IsTwoFactorEnabled from the service response instead of user.TwoFactorEnabled
            var isTwoFactorEnabled = await _userManager.GetTwoFactorEnabledAsync(user);
            if (isTwoFactorEnabled)
            {
                var token = loginOtpResponse.Response.Token;
                var message = new Message(
                    new string[] { user?.Email ?? string.Empty },
                    "OTP Confirmation",
                    token
                );

                _emailService.SendEmail(message);

                return Ok(new Response
                {
                    IsSuccess = true,
                    Status = "Success",
                    Message = $"OTP sent to email {user?.Email}."
                });
            }

            // 2FA not enabled — return JWT directly
            if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
            {
                var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
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

            return Unauthorized(new Response
            {
                IsSuccess = false,
                Status = "Error",
                Message = "Invalid username or password."
            });
        }

        [HttpPost("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string username)
        {
            var user = await _userManager.FindByNameAsync(username);

            if (user == null)
            {
                return StatusCode(StatusCodes.Status404NotFound,
                    new Response { Status = "Error", Message = "User not found." });
            }

            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);

            if (signIn.Succeeded)
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

            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Error", Message = "Invalid OTP code." });
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
                var forgetPasswordLink = Url.Action(nameof(ResetPassword), "Authentication", new { token, email = user.Email }, Request.Scheme);
                var message = new Message(new string[] { user.Email! }, "Forgot Password Link", forgetPasswordLink!);
                _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"Password reset request sent to {user.Email}. Please check your email." });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                new Response { Status = "Error", Message = "Could not send link to email, please try again." });
        }

        [HttpGet("reset-password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new { model });
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
                    new Response { Status = "Success", Message = "Password has been reset successfully." });
            }

            return StatusCode(StatusCodes.Status400BadRequest,
                new Response { Status = "Error", Message = "Could not reset password, please try again." });
        }

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