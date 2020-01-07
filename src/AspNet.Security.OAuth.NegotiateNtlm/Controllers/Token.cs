using System;
using System.Collections.Generic;
using System.Text;
using System.Text.Json.Serialization;

namespace AspNet.Security.OAuth.NegotiateNtlm.Controllers
{
    public class Token
    {
        [JsonPropertyName("access_token")]
        public String Access { get; set; }
        [JsonPropertyName("token_type"), JsonConverter(typeof(JsonStringEnumConverter))]
        public TokenKind Kind { get; set; }
        [JsonPropertyName("expires_in")]
        public UInt16 ExpiresIn { get; set; }
        [JsonPropertyName("scope")]
        public String Scope { get; set; }
        [JsonPropertyName("id_token")]
        public String Id { get; set; }
    }
    public enum TokenKind
    {
        bearer = 1,
        mac = 2,
    }
}
