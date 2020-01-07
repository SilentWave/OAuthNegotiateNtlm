using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace AspNet.Security.OAuth.NegotiateNtlm.Controllers
{
    public class UserInformation
    {
        [JsonPropertyName("sub")]
        public String Sub { get; set; }

        [JsonPropertyName("name")]
        public String Name { get; set; }

        [JsonPropertyName("given_name")]
        public String GivenName { get; set; }

        [JsonPropertyName("family_name")]
        public String FamilyName { get; set; }

        [JsonPropertyName("preferred_username")]
        public String PreferredUsername { get; set; }

        [JsonPropertyName("email")]
        public String Email { get; set; }

        /// <summary>
        /// The url of the picture not bytes
        /// </summary>
        [JsonPropertyName("picture")]
        public String Picture { get; set; }
    }
}
