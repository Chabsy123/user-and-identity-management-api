using Microsoft.AspNetCore.Identity;
using user_management_data.Models;
using user_management_service.Models;
using user_management_service.Models.Authentication.Login;
using user_management_service.Models.Authentication.SignUp;
using user_management_service.Models.Authentication.User;

namespace user_management_service.Services
{
    public interface IUserManagement
    {
        Task<ApiResponse<CreateUserResponse>> CreateUserWithTokenAsync(RegisterUser registerUser);
        Task<ApiResponse<List<string>>> AssignRoleToUserAsync(List<string> roles, ApplicationUser user);
        Task<ApiResponse<LoginOtpResponse>> GetOtpByLoginAsync(LoginModel loginModel);

        Task<ApiResponse<LoginResponse>>GetJwtTokenAsync(ApplicationUser user);

        Task<ApiResponse<LoginResponse>> LoginUserWithJwtTokenAsync(string otp, string userName);

        Task<ApiResponse<LoginResponse>> RenewAccessTokenAsync(LoginResponse tokens);



    }
}
