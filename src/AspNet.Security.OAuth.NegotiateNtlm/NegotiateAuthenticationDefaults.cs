using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using System;

namespace AspNet.Security.OAuth.NegotiateNtlm
{
    /// <summary>
    /// Default values used by the Amazon authentication middleware.
    /// </summary>
    public static class NegotiateAuthenticationDefaults
    {
        public const string AuthPersistenceKey = nameof(AuthPersistence);
        public const string NegotiateVerb = "Negotiate";
        public const string AuthHeaderPrefix = NegotiateVerb + " ";
        /// <summary>
        /// Default value for <see cref="AuthenticationScheme.Name"/>.
        /// </summary>
        public const string AuthenticationScheme = "Negotiate/NTLM";

        /// <summary>
        /// Default value for <see cref="AuthenticationScheme.DisplayName"/>.
        /// </summary>
        public const string DisplayName = "Negotiate";

        /// <summary>
        /// Default value for <see cref="AuthenticationSchemeOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "Negotiate";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public static readonly string CallbackPath = $"/{nameof(Controllers.Negotiate)}/{nameof(Controllers.Negotiate.Callback)}";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.AuthorizationEndpoint"/>.
        /// </summary>
        public static readonly string AuthorizationEndpoint = $"/{nameof(Controllers.Negotiate)}/{nameof(Controllers.Negotiate.ChallengeBrowser)}";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.TokenEndpoint"/>.
        /// </summary>
        public static readonly String TokenEndpoint = $"/{nameof(Controllers.Negotiate)}/{nameof(Controllers.Negotiate.Token)}";

        /// <summary>
        /// Default value for <see cref="OAuthOptions.UserInformationEndpoint"/>.
        /// </summary>
        public static readonly String UserInformationEndpoint = $"/{nameof(Controllers.Negotiate)}/{nameof(Controllers.Negotiate.UserInformation)}";
    }
}