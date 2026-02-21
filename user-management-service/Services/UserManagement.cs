using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using user_management_data.Models;
using user_management_service.Models;
using user_management_service.Models.Authentication.Login;
using user_management_service.Models.Authentication.SignUp;
using user_management_service.Models.Authentication.User;

namespace user_management_service.Services
{
    public class UserManagement : IUserManagement
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        public UserManagement(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager,
            IConfiguration configuration, IEmailService emailService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        public async Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user)
        {
            var assignedRoles = new List<string>();
            foreach (var role in roles)
            {
                if (await _roleManager.RoleExistsAsync(role))
                {
                    if (!await _userManager.IsInRoleAsync(user, role))
                    {
                        await _userManager.AddToRoleAsync(user, role);
                        assignedRoles.Add(role);
                    }

                }
            }
            return new ApiResponse<List<string>> { IsSuccess = true, StatusCode = 200, Message = "Roles assigned successfully", Response = assignedRoles };
        }

        public async Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser)
        {
            if (string.IsNullOrWhiteSpace(registerUser.Email))
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = "Email is required"
                };

            if (string.IsNullOrWhiteSpace(registerUser.Password))
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = "Password is required"
                };

            var userExist = await _userManager.FindByEmailAsync(registerUser.Email);
            if (userExist != null)
            {
                return new ApiResponse<CreateUserResponse> { IsSuccess = false, StatusCode = 403, Message = "User already exists" };
            }
            ApplicationUser user = new()
            {
                Email = registerUser.Email,
                Id = Guid.NewGuid().ToString(),
                UserName = registerUser.Username,
                TwoFactorEnabled = true
            };
            var result = await _userManager.CreateAsync(user, registerUser.Password);

            // Temporary debug
            var checkUser = await _userManager.FindByEmailAsync(registerUser.Email);
            Console.WriteLine($"TwoFactorEnabled after registration: {checkUser?.TwoFactorEnabled}");
            if (!result.Succeeded)
            {
                var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                return new ApiResponse<CreateUserResponse>
                {
                    IsSuccess = false,
                    StatusCode = 500,
                    Message = errors
                };
            }

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            return new ApiResponse<CreateUserResponse>
            {
                Response = new CreateUserResponse
                {
                    User = user,
                    Token = token
                },
                IsSuccess = true,
                StatusCode = 200,
                Message = "User created successfully"
            };
        }

        public async Task<ApiResponse<LoginResponse>> GetJwtTokenAsync(ApplicationUser user)
        {

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }

            var jwtToken = GetToken(authClaims); //access token
            var refreshToken = GenerateRefreshToken();
            _ = int.TryParse(_configuration["JWT:RefreshTokenValidity"], out int refreshTokenValidity);

            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiry = DateTime.UtcNow.AddDays(refreshTokenValidity);

            await _userManager.UpdateAsync(user);


            return new ApiResponse<LoginResponse>
            {
                Response = new LoginResponse()
                {
                    AccessToken = new TokenType()
                    {
                        Token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                        ExpiryTokenDate = jwtToken.ValidTo
                    },
                    RefreshToken = new TokenType()
                    {
                        Token = user.RefreshToken,
                        ExpiryTokenDate = (DateTime)user.RefreshTokenExpiry
                    }
                },

                IsSuccess = true,
                StatusCode = 200,
                Message = $"Token created"
            };
        }

        public async Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel)
        {
            if (loginModel?.Username == null || loginModel.Password == null)
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    IsSuccess = false,
                    StatusCode = 400,
                    Message = "Username or Password cannot be null."
                };
            }

            var user = await _userManager.FindByNameAsync(loginModel.Username);
            if (user == null)
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    IsSuccess = false,
                    StatusCode = 404,
                    Message = "User not found"
                };
            }

            var passwordValid = await _userManager.CheckPasswordAsync(user, loginModel.Password);
            if (!passwordValid)
            {
                return new ApiResponse<LoginOtpResponse>
                {
                    IsSuccess = false,
                    StatusCode = 401,
                    Message = "Invalid password"
                };
            }

            if (user.TwoFactorEnabled)
            {
                // Use SignInManager to properly initiate 2FA flow
                await _signInManager.SignInAsync(user, isPersistent: false);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");

                if (string.IsNullOrEmpty(token))
                {
                    return new ApiResponse<LoginOtpResponse>
                    {
                        IsSuccess = false,
                        StatusCode = 500,
                        Message = "Failed to generate OTP token"
                    };
                }

                return new ApiResponse<LoginOtpResponse>
                {
                    Response = new LoginOtpResponse
                    {
                        User = user,
                        IsTwoFactorEnabled = true,
                        Token = token
                    },
                    IsSuccess = true,
                    StatusCode = 200,
                    Message = $"OTP generated and sent to email {user.Email ?? string.Empty}"
                };
            }

            return new ApiResponse<LoginOtpResponse>
            {
                Response = new LoginOtpResponse
                {
                    User = user,
                    IsTwoFactorEnabled = false,
                    Token = string.Empty
                },
                IsSuccess = true,
                StatusCode = 200,
                Message = "Two-factor authentication is not enabled for this user."
            };
        }

        public async Task<ApiResponse<LoginResponse>> LoginUserWithJwtTokenAsync(string otp, string userName)
        {
            var user = await _userManager.FindByNameAsync(userName);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", otp, false, false);
            if (signIn.Succeeded)
            {
                if (user != null)
                {
                    return await GetJwtTokenAsync(user);
                }
            }
            return new ApiResponse<LoginResponse>()
            {

                Response = new LoginResponse()
                {

                },
                IsSuccess = false,
                StatusCode = 400,
                Message = $"Invalid Otp"
            };
        }

        public async Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens)
        {
            var accessToken = tokens.AccessToken;
            var refreshToken = tokens.RefreshToken;
            var principal = GetClaimsPrincipal(accessToken.Token);
            var user = await _userManager.FindByNameAsync(principal.Identity.Name);
            if (refreshToken.Token != user.RefreshToken && refreshToken.ExpiryTokenDate <= DateTime.Now)
            {
                return new ApiResponse<LoginResponse>
                {

                    IsSuccess = false,
                    StatusCode = 400,
                    Message = $"Token invalid or expired"
                };
            }

            var response = await GetJwtTokenAsync(user);
            return response;
        }

        #region PrivateMethods
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            _ = int.TryParse(_configuration["JWT:TokenValidityInMinutes"], out int tokenValidityInMinutes);
            var expirationTimeUtc = DateTime.UtcNow.AddMinutes(tokenValidityInMinutes);
            var localTimeZone = TimeZoneInfo.Local;
            var expirationTimeInLocalTimeZone = TimeZoneInfo.ConvertTimeFromUtc(expirationTimeUtc, localTimeZone);

            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: expirationTimeInLocalTimeZone,
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

            return token;
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new Byte[64];
            var range = RandomNumberGenerator.Create();
            range.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }
        private ClaimsPrincipal GetClaimsPrincipal(string accessToken)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"])),
                ValidateLifetime = false
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(accessToken, tokenValidationParameters, out SecurityToken securityToken);

            return principal;
        }


        #endregion
    }
}