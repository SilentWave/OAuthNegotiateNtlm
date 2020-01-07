
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;

namespace AspNet.Security.OAuth.NegotiateNtlm
{
    /// <summary>
    /// Defines a set of options used by <see cref="AmazonAuthenticationHandler"/>.
    /// </summary>
    public class NegotiateAuthenticationOptions : OAuthOptions
    {
        /// <summary>
        /// Initializes a new instance of the <see cref="NegotiateAuthenticationOptions"/> class.
        /// </summary>
        public NegotiateAuthenticationOptions()
        {
            ClientId = "negotiate-ntlm";
            ClientSecret = "not so secret";
            ClaimsIssuer = NegotiateAuthenticationDefaults.Issuer;
            CallbackPath = NegotiateAuthenticationDefaults.CallbackPath;

            AuthorizationEndpoint = NegotiateAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = NegotiateAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = NegotiateAuthenticationDefaults.UserInformationEndpoint;

            Scope.Add("profile");
            Scope.Add("profile:user_id");

            //ClaimActions.MapJsonKey(ClaimTypes.Email, "email");
            ClaimActions.MapJsonKey(ClaimTypes.Name, "name");
            ClaimActions.MapJsonKey(ClaimTypes.NameIdentifier, "sub");
            //ClaimActions.MapJsonKey(ClaimTypes.PostalCode, "postal_code");
        }

        /// <summary>
        /// Gets the list of fields to retrieve from the user information endpoint.
        /// </summary>
        public ISet<string> Fields { get; } = new HashSet<string>
        {
            "email",
            "name",
            "user_id"
        };

        internal INegotiateStateFactory StateFactory { get; set; } = new ReflectedNegotiateStateFactory();
        internal bool PersistKerberosCredentials { get; set; }
        internal bool PersistNtlmCredentials { get; set; }
    }
}