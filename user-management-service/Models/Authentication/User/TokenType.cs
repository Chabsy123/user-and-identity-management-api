using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace user_management_service.Models.Authentication.User
{
    public class TokenType
    {
        public string Token { get; set; } = null!;
        public DateTime ExpiryTokenDate { get; set; }
    }
}
