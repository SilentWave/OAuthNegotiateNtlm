using System;
using AspNet.Security.OAuth.NegotiateNtlm;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Extension methods to add Negotiate authentication capabilities to an HTTP application pipeline.
    /// </summary>
    public static class NegotiateAuthenticationExtensions
    {
        /// <summary>
        /// Adds <see cref="NegotiateAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Negotiate authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddNegotiate([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddNegotiate(NegotiateAuthenticationDefaults.AuthenticationScheme, options => { });
        }

        /// <summary>
        /// Adds <see cref="NegotiateAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Negotiate authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the Negotiate options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddNegotiate(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<NegotiateAuthenticationOptions> configuration)
        {
            return builder.AddNegotiate(NegotiateAuthenticationDefaults.AuthenticationScheme, configuration);
        }

        /// <summary>
        /// Adds <see cref="NegotiateAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Negotiate authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the Negotiate options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddNegotiate(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme,
            [NotNull] Action<NegotiateAuthenticationOptions> configuration)
        {
            return builder.AddNegotiate(scheme, NegotiateAuthenticationDefaults.DisplayName, configuration);
        }

        /// <summary>
        /// Adds <see cref="NegotiateAuthenticationHandler"/> to the specified
        /// <see cref="AuthenticationBuilder"/>, which enables Negotiate authentication capabilities.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="caption">The optional display name associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the Negotiate options.</param>
        /// <returns>The <see cref="AuthenticationBuilder"/>.</returns>
        public static AuthenticationBuilder AddNegotiate(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] string scheme, [CanBeNull] string caption,
            [NotNull] Action<NegotiateAuthenticationOptions> configuration)
        {
            return builder.AddOAuth<NegotiateAuthenticationOptions, NegotiateAuthenticationHandler>(scheme, caption, configuration);
        }
    }
}