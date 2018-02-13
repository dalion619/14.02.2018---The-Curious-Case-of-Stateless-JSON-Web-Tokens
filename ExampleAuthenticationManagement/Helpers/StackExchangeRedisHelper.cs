using StackExchange.Redis;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Threading.Tasks;
using System.Web;

namespace ExampleAuthenticationManagement.Helpers
{
    public static class StackExchangeRedisHelper
    {
        public static async Task<T> Get<T>(this IDatabase cache, string key)
        {
            return Deserialize<T>(await cache.StringGetAsync(key));
        }

        public static async Task<string> GetAsync(this IDatabase cache, string key)
        {
            return Deserialize<string>(await cache.StringGetAsync(key));
        }

        public static void Set(this IDatabase cache, string key, string value)
        {
            cache.StringSet(key, Serialize(value));
            cache.KeyExpire(key, DateTime.UtcNow.AddMinutes(30));
        }

        static byte[] Serialize(object o)
        {
            if (o == null)
            {
                return null;
            }
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            using (MemoryStream memoryStream = new MemoryStream())
            {
                binaryFormatter.Serialize(memoryStream, o);
                byte[] objectDataAsStream = memoryStream.ToArray();
                return objectDataAsStream;
            }
        }

        static T Deserialize<T>(byte[] stream)
        {
            BinaryFormatter binaryFormatter = new BinaryFormatter();
            if (stream == null)
                return default(T);

            using (MemoryStream memoryStream = new MemoryStream(stream))
            {
                T result = (T)binaryFormatter.Deserialize(memoryStream);
                return result;
            }
        }
    }
}