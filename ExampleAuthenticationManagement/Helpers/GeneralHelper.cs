using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Web;

namespace ExampleAuthenticationManagement.Helpers
{
    public static class GeneralHelper
    {
        public static string GetHash(string input)
        {
            HashAlgorithm hashAlgorithm = new SHA256CryptoServiceProvider();

            byte[] byteValue = System.Text.Encoding.UTF8.GetBytes(input);

            byte[] byteHash = hashAlgorithm.ComputeHash(byteValue);

            return Convert.ToBase64String(byteHash);
        }

        private static string GetRandomCryptoBase64String()
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[4];
                rng.GetBytes(tokenData);


                return Convert.ToBase64String(tokenData);

            }
        }

        private static short GetRandomCryptoSubstringLengthNumber()
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[32];
                rng.GetBytes(tokenData);

                var random = BitConverter.ToInt16(tokenData, 0);
                return random;

            }
        }

        private static string GetRandomCryptoString()
        {
            using (RandomNumberGenerator rng = new RNGCryptoServiceProvider())
            {
                byte[] tokenData = new byte[4096];
                rng.GetBytes(tokenData);

                var rand = BitConverter.ToInt64(tokenData, 0);
                var random = BitConverter.ToInt16(tokenData, 0);

                const Decimal OldRange = (Decimal)int.MaxValue - (Decimal)int.MinValue;
                var unixEpoch = new DateTime(1970, 1, 1);
                var y2k = new DateTime(2000,1, 1).AddDays(random);
                var dateTimeNow = DateTime.Now;

                var min = (Int64)dateTimeNow.Subtract(unixEpoch).TotalMilliseconds;
                var max = (Int64)dateTimeNow.Subtract(y2k).TotalMilliseconds;

                Decimal NewRange = max - min;
                Decimal NewValue = ((Decimal)rand - (Decimal)int.MinValue) / OldRange * NewRange + (Decimal)min;
                var val = NewValue.ToString().Replace("-", "").Replace(".", "");
                return val;

            }
        }

        public static string GenerateJWTRedisKey()
        {

            var str = "";
            for (int c = 0; c < 10; c++)
            {
                str = str + GetRandomCryptoString() + GetRandomCryptoBase64String();
            }

            short substringLen = 0;
            while (substringLen <= 127 || substringLen > 256)
            {
                substringLen = GetRandomCryptoSubstringLengthNumber();
            }

            return str.Substring(0, substringLen);
           

        }

        public static string GetForwardedOrRemoteIPAddress()
        {
            string ipAddress = HttpContext.Current.Request.ServerVariables["HTTP_X_FORWARDED_FOR"];
            if (!string.IsNullOrEmpty(ipAddress))
            {
                ipAddress = ipAddress.Split(':')[0];
            }
            else
            {
                ipAddress = HttpContext.Current.Request.ServerVariables["REMOTE_ADDR"];
                if (ipAddress == "::1")
                {
                    ipAddress = "127.0.0.1";
                }
            }
            return ipAddress;
        }

        public static string GetPrettyDate(DateTime d)
        {
            var now = DateTime.UtcNow;
            
            TimeSpan s = now.Subtract(d);
            
            int dayDiff = (int)s.TotalDays;

            

            int secDiff = (int)s.TotalSeconds;

            

            if (dayDiff < 0 || dayDiff >= 367)
            {
                return null;
            }

            

            if (dayDiff == 0)
            {
               

                if (secDiff < 60)
                {
                    return "just now";
                }
               

                if (secDiff < 120)
                {
                    return "1 minute ago";
                }
                

                if (secDiff < 3600)
                {
                    return string.Format("{0} minutes ago",
                        Math.Floor((double)secDiff / 60));
                }
                

                if (secDiff < 7200)
                {
                    return "1 hour ago";
                }
                

                if (secDiff < 86400)
                {
                    return string.Format("{0} hours ago",
                        Math.Floor((double)secDiff / 3600));
                }
            }
            

            if (dayDiff == 1)
            {
                return "yesterday";
            }
            if (dayDiff < 7)
            {
                return string.Format("{0} days ago",
                dayDiff);
            }
            if (dayDiff < 31)
            {
                return string.Format("{0} weeks ago",
                Math.Ceiling((double)dayDiff / 7));
            }
            if (dayDiff < 365)
            {
                return string.Format("{0} months ago",
                Math.Ceiling((double)dayDiff / 30));
            }
            return null;
        }
    }
}