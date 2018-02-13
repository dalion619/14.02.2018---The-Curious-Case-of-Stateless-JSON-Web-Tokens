using Microsoft.AspNet.Identity.Owin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ExampleAuthenticationManagement.Helpers
{
    public class UserManagerHelper : IDisposable
    {
        private ApplicationSignInManager _userManager;
        public UserManagerHelper()
        {
            UserManager = HttpContext.Current.GetOwinContext().GetUserManager<ApplicationSignInManager>();
        }
        public ApplicationSignInManager UserManager
        {
            get
            {
                return _userManager ?? HttpContext.Current.GetOwinContext().Get<ApplicationSignInManager>();
            }
            private set
            {
                _userManager = value;
            }
        }
        public void Dispose()
        {
            if (_userManager != null)
            {
                _userManager.Dispose();
                _userManager = null;
            }
        }

    }

}