using ExampleAuthenticationManagement.Helpers;
using ExampleAuthenticationManagement.Models;
using Microsoft.AspNet.Identity;
using Newtonsoft.Json;
using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;

namespace ExampleAuthenticationManagement.Controllers
{
    public class HomeController : Controller
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
        public async Task<ActionResult> Index()
        {
            IDatabase cache = Connection.GetDatabase();
            var model = new List<TokenViewModel>();
            ViewBag.Title = "Home Page";
            if (Request.IsAuthenticated)
            {
                var userId = User.Identity.GetUserId();
                var userPointers =await TokenHelper.GetUserPointersFromRedis(userId);
                foreach (var t in userPointers.Pointers)
                {
                    var token = (string)await cache.GetAsync(t);
                    if (!string.IsNullOrEmpty(token))
                    {
                        var authToken = JsonConvert.DeserializeObject<AuthServiceTokenResponse>(token);

                        model.Add(new TokenViewModel() { IP = authToken.ip_address, UserAgent = authToken.user_agent, LastActive = GeneralHelper.GetPrettyDate(authToken.LastAccessed) });
                    }
                }
              
            }
            return View(model);
        }
    }
}
