using Microsoft.AspNetCore.Identity;
using System.Threading.Tasks;

namespace WebApp.Identity
{
    public class NotContainsPasswordValidator<TUser> : IPasswordValidator<TUser> where TUser : class
    {
        public async Task<IdentityResult> ValidateAsync(UserManager<TUser> manager, TUser user, string password)
        {
            var username = await manager.GetUserNameAsync(user);

            if (username == password)
                return IdentityResult.Failed(new IdentityError { Description = "A senha não pode ser igual ao password" });
            if(password.Contains("Password"))
                return IdentityResult.Failed(new IdentityError { Description = "A senha não pode ser igual ao password" });

            return IdentityResult.Success;

        }
    }
}
