using ExampleAuthenticationManagement.Helpers;
using Microsoft.Owin.Security.DataHandler.Encoder;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.ServiceModel.Security.Tokens;
using System.Threading.Tasks;
using System.Web;
using System.Web.Http;
using System.Web.Mvc;
using System.Web.Optimization;
using System.Web.Routing;

namespace ExampleAuthenticationManagement
{
    public class WebApiApplication : System.Web.HttpApplication
    {
        protected void Application_Start()
        {
            AreaRegistration.RegisterAllAreas();
            GlobalConfiguration.Configure(WebApiConfig.Register);
            FilterConfig.RegisterGlobalFilters(GlobalFilters.Filters);
            RouteConfig.RegisterRoutes(RouteTable.Routes);
            BundleConfig.RegisterBundles(BundleTable.Bundles);
        }

        public WebApiApplication()
        {
            var wrapper = new EventHandlerTaskAsyncHelper(CheckAuth);
            this.AddOnAcquireRequestStateAsync(wrapper.BeginEventHandler, wrapper.EndEventHandler);
        }

        private async Task CheckAuth(object sender, EventArgs e)
        {
            var app = (HttpApplication)sender;
            var ctx = app.Context;

            if (Request.RawUrl.Contains("__browserLink"))
            {
                return;
            }


            if (Request.RawUrl.Contains("LogOff"))
            {
                Response.Cookies[ConfigurationManager.AppSettings["PointerTokenCookieName"]].Expires = DateTime.UtcNow.AddDays(-1);
                return;
            }

            var pointerCookie = Request.Cookies[ConfigurationManager.AppSettings["PointerTokenCookieName"]];
            if (pointerCookie == null)
            {
                return;
            }
            var tokenAuthenticity = await TokenHelper.CheckTokenAuthenticity(pointerCookie.Value);
            if (!tokenAuthenticity)
            {
                return;
            }
            var tokenCheck =await  TokenHelper.CheckTokenValidTo(pointerCookie.Value);
            if (!tokenCheck)
            {
                var refreshedToken = await TokenHelper.RefreshToken(pointerCookie.Value);
                var newPointerCookie = await TokenHelper.GetPointerCookie(pointerCookie.Value);
                Response.Cookies.Add(newPointerCookie);
            }
            
            await TokenHelper.SetTokenForUser(pointerCookie.Value);
            
            return;
        }

    }
}
