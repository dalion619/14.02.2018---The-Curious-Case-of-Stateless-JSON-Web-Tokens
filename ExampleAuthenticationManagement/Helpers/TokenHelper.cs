using Microsoft.Owin.Security.DataHandler.Encoder;
using Newtonsoft.Json;
using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.Configuration;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Net.Http;
using System.ServiceModel.Security.Tokens;
using System.Threading.Tasks;
using System.Web;

namespace ExampleAuthenticationManagement.Helpers
{
    public static class TokenHelper
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
        private static string pointerTokenCookieName = ConfigurationManager.AppSettings["PointerTokenCookieName"];

        public static bool ValidateIPAddress()
        {
            return Convert.ToBoolean(ConfigurationManager.AppSettings["ValidateIPAddress"]);
        }
        public static bool ValidateUserAgent()
        {
            return Convert.ToBoolean(ConfigurationManager.AppSettings["ValidateUserAgent"]);
        }
        public static bool EnableSingleSession()
        {
            return Convert.ToBoolean(ConfigurationManager.AppSettings["EnableSingleSession"]);
        }

        public async static Task<string> GetTokenFromAuthService(string email, string password, string tenant)
        {


            string ipAddress = GeneralHelper.GetForwardedOrRemoteIPAddress();
            var formContent = new FormUrlEncodedContent(new[]
    {
    new KeyValuePair<string, string>("grant_type", "password"),
    new KeyValuePair<string, string>("username", email),
    new KeyValuePair<string, string>("password", password),
    new KeyValuePair<string, string>("client_id", tenant),
    new KeyValuePair<string, string>("user_agent",  HttpContext.Current.Request.ServerVariables["HTTP_USER_AGENT"]),
    new KeyValuePair<string, string>("ip_address", ipAddress)
});
            using (var httpClient = new HttpClient())
            {
                var result = await httpClient.PostAsync(ConfigurationManager.AppSettings["AuthUrl"] + "/oauth/token", formContent);
                if (result.StatusCode != System.Net.HttpStatusCode.OK)
                {
                    return null;
                }
                return await result.Content.ReadAsStringAsync();
            }


        }
        public async static Task<string> AddTokenToRedis(string authJson, bool useRefreshTokenTimeSpan)
        {
            var authToken = JsonConvert.DeserializeObject<AuthServiceTokenResponse>(authJson);

            IDatabase cache = Connection.GetDatabase();
            var pointer = GeneralHelper.GenerateJWTRedisKey();
            authToken.pointer = pointer;
            authToken.LastAccessed = DateTime.UtcNow;
            authToken.useRefreshTokenTimeSpan = useRefreshTokenTimeSpan;
            cache.Set(pointer, JsonConvert.SerializeObject(authToken));
            var expires = TimeSpan.FromSeconds(authToken.expires_in);
            if (useRefreshTokenTimeSpan)
            {

                expires = TimeSpan.FromMinutes(Convert.ToDouble(ConfigurationManager.AppSettings["RefreshTokenTimeSpanMinutes"]));

            }

            cache.KeyExpire(pointer, expires);
            await AddUserPointerToRedis(authToken.userId, pointer, expires);
            return pointer;
        }
        public static async Task<bool> SetTokenForUser(string pointer)
        {
            var authToken = await GetTokenFromRedis(pointer);

            byte[] audienceSecret = TextEncodings.Base64Url.Decode(ConfigurationManager.AppSettings["AuthTokenAudienceSecret"]);
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters()
            {
                ValidAudience = ConfigurationManager.AppSettings["AuthTokenAudienceId"],
                ValidIssuer = ConfigurationManager.AppSettings["AuthUrl"],
                IssuerSigningToken = new BinarySecretSecurityToken(audienceSecret)
            };

            SecurityToken securityToken;
            var principal = tokenHandler.ValidateToken(authToken.access_token, validationParameters, out securityToken);
            HttpContext.Current.User = principal;
            return true;
        }

        public async static Task<AuthServiceTokenResponse> GetTokenFromRedis(string pointer)
        {
            IDatabase cache = Connection.GetDatabase();
            var authJson = (string)await cache.GetAsync(pointer);
            if (string.IsNullOrEmpty(authJson))
            {
                return null;
            }
            var authToken = JsonConvert.DeserializeObject<AuthServiceTokenResponse>(authJson);
            authToken.LastAccessed = DateTime.UtcNow;
            cache.Set(pointer, JsonConvert.SerializeObject(authToken));

            if (authToken.useRefreshTokenTimeSpan)
            {
                cache.KeyExpire(pointer, TimeSpan.FromMinutes(Convert.ToDouble(ConfigurationManager.AppSettings["RefreshTokenTimeSpanMinutes"])));
            }
            else
            {
                cache.KeyExpire(pointer, TimeSpan.FromSeconds(authToken.expires_in));

            }

            return authToken;
        }

        public static void ClearTokenFromRedis(string pointer)
        {
            IDatabase cache = Connection.GetDatabase();
            cache.Set(pointer, string.Empty);
            cache.KeyExpire(pointer, TimeSpan.FromSeconds(1));

        }
        
        public static async Task<bool> CheckTokenValidTo(string pointer)
        {
            var authToken = await GetTokenFromRedis(pointer);
            if (authToken == null)
            {
                return false;
            }
            var access_token = authToken.access_token;
            var handler = new JwtSecurityTokenHandler();
            var tokenS = handler.ReadToken(access_token) as JwtSecurityToken;
            var minutesLeft = (tokenS.ValidTo - DateTime.UtcNow).TotalMinutes;
            if (minutesLeft <= (Convert.ToInt32(ConfigurationManager.AppSettings["AuthTokenTimeSpanMinutes"]) - 15))
            {
                return false;
            }
            return true;
        }

        public static async Task<bool> CheckTokenAuthenticity(string pointer)
        {
            var authToken = await GetTokenFromRedis(pointer);
            if (authToken == null)
            {
                return false;
            }

            if (ValidateIPAddress())
            {
                if (authToken.ip_address != GeneralHelper.GetForwardedOrRemoteIPAddress())
                {
                    return false;
                }
            }
            if (ValidateUserAgent())
            {
                if (authToken.user_agent != HttpContext.Current.Request.ServerVariables["HTTP_USER_AGENT"])
                {
                    return false;
                }
            }
            return true;
        }

        public async static Task<bool> RefreshToken(string pointer)
        {

            var token = await GetTokenFromRedis(pointer);
            if (token == null)
            {
                return false;
            }


            var formContent = new FormUrlEncodedContent(new[]
    {
            new KeyValuePair<string, string>("grant_type", "refresh_token"),
            new KeyValuePair<string, string>("refresh_token", token.refresh_token),
                new KeyValuePair<string, string>("client_id", token.client_id),
    new KeyValuePair<string, string>("user_agent", HttpContext.Current.Request.ServerVariables["HTTP_USER_AGENT"]),
    new KeyValuePair<string, string>("ip_address", GeneralHelper.GetForwardedOrRemoteIPAddress())
        });
            var response = "";

            using (var httpClient = new HttpClient())
            {
                var result = await httpClient.PostAsync(ConfigurationManager.AppSettings["AuthUrl"] + "/oauth/token", formContent);
                if (result.StatusCode != System.Net.HttpStatusCode.OK)
                {
                    return false;
                }
                response = await result.Content.ReadAsStringAsync();

            }


            var authToken = JsonConvert.DeserializeObject<AuthServiceTokenResponse>(response);

            IDatabase cache = Connection.GetDatabase();

            authToken.pointer = pointer;
            authToken.LastAccessed = token.LastAccessed;
            authToken.useRefreshTokenTimeSpan = token.useRefreshTokenTimeSpan;
            cache.Set(pointer, JsonConvert.SerializeObject(authToken));

            if (token.useRefreshTokenTimeSpan)
            {
                cache.KeyExpire(pointer, TimeSpan.FromMinutes(Convert.ToDouble(ConfigurationManager.AppSettings["RefreshTokenTimeSpanMinutes"])));

            }
            else
            {
                cache.KeyExpire(pointer, TimeSpan.FromSeconds(authToken.expires_in));

            }

            return true;


        }

        public static async Task<HttpCookie> GetPointerCookie(string pointer)
        {

            var authToken = await GetTokenFromRedis(pointer);
            HttpCookie cookie = new HttpCookie(pointerTokenCookieName);

            cookie.Value = pointer;
            if (authToken.useRefreshTokenTimeSpan)
            {
                cookie.Expires = DateTime.UtcNow.AddMinutes(Convert.ToDouble(ConfigurationManager.AppSettings["RefreshTokenTimeSpanMinutes"]));
            }
            else
            {
                cookie.Expires = DateTime.UtcNow.AddSeconds(Convert.ToDouble(authToken.expires_in));
            }
            cookie.HttpOnly = true;
            cookie.Secure = true;
            return cookie;
        }

        public static void ClearCookies()
        {

            HttpContext.Current.Request.Cookies[pointerTokenCookieName].Expires = DateTime.UtcNow.AddDays(-1);
            HttpContext.Current.Response.Cookies[pointerTokenCookieName].Expires = DateTime.UtcNow.AddDays(-1);
            HttpContext.Current.User = null;
        }

        public static async Task<RedisUserPointers> GetUserPointersFromRedis(string userId)
        {
            IDatabase cache = Connection.GetDatabase();
            var userPointersJson = (string) await cache.GetAsync(userId);
            if (string.IsNullOrEmpty(userPointersJson))
            {
                return new RedisUserPointers() { Pointers = new List<string>() };
            }
            return JsonConvert.DeserializeObject<RedisUserPointers>(userPointersJson);
        }
        public static async Task AddUserPointerToRedis(string userId, string pointer, TimeSpan expires)
        {
            IDatabase cache = Connection.GetDatabase();
            var userPointers = await GetUserPointersFromRedis(userId);
            userPointers.UserId = userId;
            var newPointer = userPointers.Pointers.SingleOrDefault(x => x == pointer);
            if (newPointer == null)
            {
                if (EnableSingleSession())
                {
                    foreach (var t in userPointers.Pointers)
                    {
                        ClearTokenFromRedis(t);
                    }
                    userPointers.Pointers = new List<string>();
                }
                userPointers.Pointers.Add(pointer);
                cache.Set(userId, JsonConvert.SerializeObject(userPointers));
                cache.KeyExpire(userId, expires);
            }
            await ClearExpiredUserTokensFromRedis(userId);           

        }

        public static async Task ClearExpiredUserTokensFromRedis(string userId)
        {
            IDatabase cache = Connection.GetDatabase();
            var userPointersJson = (string)await cache.GetAsync(userId);
            var userPointers = new RedisUserPointers() { Pointers = new List<string>(), UserId=userId };
            var useRefreshTokenTimeSpan = false;
            if (string.IsNullOrEmpty(userPointersJson))
            {
                cache.Set(userId, JsonConvert.SerializeObject(userPointers));

            }else
            {
                userPointers = JsonConvert.DeserializeObject<RedisUserPointers>(userPointersJson);
                var pointersToRemove = new List<string>();
                foreach (var t in userPointers.Pointers)
                {
                    var oldToken = (string)await cache.GetAsync(t);
                    if (string.IsNullOrEmpty(oldToken))
                    {
                        pointersToRemove.Add(t);
                    }else
                    {
                        var authToken = JsonConvert.DeserializeObject<AuthServiceTokenResponse>(oldToken);
                        if (authToken.useRefreshTokenTimeSpan)
                        {
                            useRefreshTokenTimeSpan = true;
                        }
                    }
                }
                foreach (var t in pointersToRemove)
                {
                    userPointers.Pointers.Remove(t);
                }
            }
            var expires = TimeSpan.FromMinutes(Convert.ToDouble(ConfigurationManager.AppSettings["AuthTokenTimeSpanMinutes"]));            
            if (useRefreshTokenTimeSpan)
            {

                expires = TimeSpan.FromMinutes(Convert.ToDouble(ConfigurationManager.AppSettings["RefreshTokenTimeSpanMinutes"]));

            }

            cache.Set(userId, JsonConvert.SerializeObject(userPointers));
            cache.KeyExpire(userId, expires);
        }


    }

    public class AuthServiceTokenResponse
    {
        public string client_id { get; set; }
        public string pointer { get; set; }
        public string access_token { get; set; }
        public string token_type { get; set; }
        public int expires_in { get; set; }
        public string refresh_token { get; set; }
        public string userName { get; set; }
        public string ip_address { get; set; }
        public string user_agent { get; set; }
        public string userId { get; set; }
        public DateTime LastAccessed { get; set; }
        public bool useRefreshTokenTimeSpan { get; set; }
    }

    public class RedisUserPointers
    {
        public string UserId { get; set; }
        public List<string> Pointers { get; set; }
    }
}