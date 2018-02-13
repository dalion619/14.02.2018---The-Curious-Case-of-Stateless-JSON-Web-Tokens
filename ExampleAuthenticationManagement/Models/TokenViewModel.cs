using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;

namespace ExampleAuthenticationManagement.Models
{
    public class TokenViewModel
    {
        public string IP { get; set; }
        public string UserAgent { get; set; }
        public string LastActive { get; set; }
    }
}