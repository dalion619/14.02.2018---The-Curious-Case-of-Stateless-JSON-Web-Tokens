using ExampleAuthenticationManagement.Helpers;
using ExampleAuthenticationManagement.Models;
using Microsoft.AspNet.Identity.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OAuth;
using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Data.Entity;
using System.IdentityModel.Claims;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

namespace ExampleAuthenticationManagement.Providers
{
    public class SimpleAuthorizationServerProvider : OAuthAuthorizationServerProvider
    {
        private static Lazy<ConnectionMultiplexer> lazyConnection = new Lazy<ConnectionMultiplexer>(() =>
        {
            return ConnectionMultiplexer.Connect(ConfigurationManager.ConnectionStrings["RedisConnectionString"].ConnectionString);
        });

        public static ConnectionMultiplexer Connection
        {
            get
            {
                return lazyConnection.Value;
            }
        }

        public override Task ValidateClientAuthentication(OAuthValidateClientAuthenticationContext context)
        {

            string clientId = string.Empty;
            string clientSecret = string.Empty;


            context.TryGetFormCredentials(out clientId, out clientSecret);

            context.OwinContext.Set<string>("as:clientAllowedOrigin", "*");

            context.Validated();
            return Task.FromResult<object>(null);
        }

        public override async Task GrantResourceOwnerCredentials(OAuthGrantResourceOwnerCredentialsContext context)
        {

            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");

            if (allowedOrigin == null) allowedOrigin = "*";

            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });


            using (var db = new ApplicationDbContext())
            {
                using (var usermanager = new UserManagerHelper())
                {
                    ApplicationUser dbUser = null;


                    dbUser = await db.Users.SingleOrDefaultAsync(x => x.Email == context.UserName && x.Tenant == context.ClientId);
                    if (dbUser == null)
                    {
                        context.SetError("invalid_grant", "The user name or password is incorrect.");
                        return;
                    }
                    if (!await usermanager.UserManager.UserManager.CheckPasswordAsync(dbUser, context.Password))
                    {

                        context.SetError("invalid_grant", "The user name or password is incorrect.");
                        return;
                    }

                    if (dbUser == null)
                    {
                        context.SetError("invalid_grant", "The user name or password is incorrect.");
                        return;
                    }



                    var identity = await dbUser.GenerateUserIdentityAsync(context.OwinContext.GetUserManager<ApplicationUserManager>(), "JWT");

                    var props = new AuthenticationProperties(new Dictionary<string, string>
                {

                    {
                        "client_id", context.ClientId
                    },
                    {
                        "userId", dbUser.Id
                    },
                    {
                        "userName", context.UserName
                    },
                    {
                        "ip_address", HttpContext.Current.Request.Form["ip_address"]
                    },
                    {
                        "user_agent", HttpContext.Current.Request.Form["user_agent"]
                    },
                    {
                        "env", ConfigurationManager.AppSettings["Environment"]
                    }
                });

                    var ticket = new AuthenticationTicket(identity, props);
                    context.Validated(ticket);


                }
            }
        }

        public override Task TokenEndpoint(OAuthTokenEndpointContext context)
        {
            foreach (KeyValuePair<string, string> property in context.Properties.Dictionary)
            {
                context.AdditionalResponseParameters.Add(property.Key, property.Value);
            }

            return Task.FromResult<object>(null);
        }

        public override Task GrantRefreshToken(OAuthGrantRefreshTokenContext context)
        {
            var originalClient = context.Ticket.Properties.Dictionary["client_id"];
            var currentClient = context.ClientId;

            var originalIPAddress = context.Ticket.Properties.Dictionary["ip_address"];
            var currentIPAddress = HttpContext.Current.Request.Form["ip_address"];

            var originalUserAgent = context.Ticket.Properties.Dictionary["user_agent"];
            var currentUserAgent = HttpContext.Current.Request.Form["user_agent"];


            if (originalClient != currentClient)
            {
                context.SetError("invalid_clientId", "Refresh token is issued to a different clientId.");
                return Task.FromResult<object>(null);
            }
            if (TokenHelper.ValidateIPAddress())
            {
                if (originalIPAddress != currentIPAddress)
                {
                    context.SetError("invalid_IP_Address", "Refresh token is issued to a different IP Address.");
                    return Task.FromResult<object>(null);
                }
            }
            if (TokenHelper.ValidateUserAgent())
            {
                if (originalUserAgent != currentUserAgent)
                {
                    context.SetError("invalid_User_Agent", "Refresh token is issued to a different device.");
                    return Task.FromResult<object>(null);
                }
            }
            // Change auth ticket for refresh token requests
            var newIdentity = new ClaimsIdentity(context.Ticket.Identity);
            newIdentity.AddClaim(new System.Security.Claims.Claim("newClaim", "newValue"));

            var newTicket = new AuthenticationTicket(newIdentity, context.Ticket.Properties);
            context.Validated(newTicket);

            return Task.FromResult<object>(null);
        }

        public override Task TokenEndpointResponse(OAuthTokenEndpointResponseContext context)
        {
            return base.TokenEndpointResponse(context);
        }

    }
}