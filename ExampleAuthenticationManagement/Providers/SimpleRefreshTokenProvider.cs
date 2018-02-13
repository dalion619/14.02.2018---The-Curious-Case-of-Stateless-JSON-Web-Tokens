using ExampleAuthenticationManagement.Helpers;
using ExampleAuthenticationManagement.Models;
using Microsoft.Owin.Security.Infrastructure;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;

namespace ExampleAuthenticationManagement.Providers
{
    public class SimpleRefreshTokenProvider : IAuthenticationTokenProvider
    {

        public async Task CreateAsync(AuthenticationTokenCreateContext context)
        {
            var clientid = context.Ticket.Properties.Dictionary["client_id"];

            if (string.IsNullOrEmpty(clientid))
            {
                return;
            }

            var refreshTokenId = Guid.NewGuid().ToString("n");

            using (var db = new ApplicationDbContext())
            {

                var token = new RefreshToken()
                {
                    Id = GeneralHelper.GetHash(refreshTokenId),
                    ClientId = clientid,
                    Subject = context.Ticket.Identity.Name,
                    IssuedUtc = DateTime.UtcNow,
                    ExpiresUtc = DateTime.UtcNow.AddMinutes(Convert.ToDouble(ConfigurationManager.AppSettings["RefreshTokenTimeSpanMinutes"]))
                };

                context.Ticket.Properties.IssuedUtc = token.IssuedUtc;
                context.Ticket.Properties.ExpiresUtc = token.ExpiresUtc;

                token.ProtectedTicket = context.SerializeTicket();

                db.RefreshTokens.Add(token);

                if (await db.SaveChangesAsync() == 1)
                {
                    context.SetToken(refreshTokenId);

                }

            }
        }


        public async Task ReceiveAsync(AuthenticationTokenReceiveContext context)
        {
            var allowedOrigin = context.OwinContext.Get<string>("as:clientAllowedOrigin");
            context.OwinContext.Response.Headers.Add("Access-Control-Allow-Origin", new[] { allowedOrigin });

            string hashedTokenId = GeneralHelper.GetHash(context.Token);

            using (var db = new ApplicationDbContext())
            {
                var refreshToken = db.RefreshTokens.SingleOrDefault(x => x.Id == hashedTokenId);

                if (refreshToken != null)
                {
                    //Get protectedTicket from refreshToken class
                    context.DeserializeTicket(refreshToken.ProtectedTicket);
                    var result = db.RefreshTokens.Remove(refreshToken);
                }
                await db.SaveChangesAsync();
            }
        }

        void IAuthenticationTokenProvider.Create(AuthenticationTokenCreateContext context)
        {
            throw new NotImplementedException();
        }

        void IAuthenticationTokenProvider.Receive(AuthenticationTokenReceiveContext context)
        {
            throw new NotImplementedException();
        }


    }
}