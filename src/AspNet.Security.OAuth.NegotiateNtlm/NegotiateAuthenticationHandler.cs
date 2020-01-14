using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Security.Principal;
using System.Text.Encodings.Web;
using System.Text.Json;
using System.Threading.Tasks;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;

namespace AspNet.Security.OAuth.NegotiateNtlm
{
    /// <summary>
    /// Defines a handler for authentication using Amazon.
    /// </summary>
    public class NegotiateAuthenticationHandler : OAuthHandler<OAuthNegotiateAuthenticationOptions>
    {
        private const string NegotiateVerb = "Negotiate";

        /// <summary>
        /// Initializes a new instance of the <see cref="NegotiateAuthenticationHandler"/> class.
        /// </summary>
        /// <param name="options">The authentication options.</param>
        /// <param name="logger">The logger to use.</param>
        /// <param name="encoder">The URL encoder to use.</param>
        /// <param name="clock">The system clock to use.</param>
        public NegotiateAuthenticationHandler(
            [NotNull] IOptionsMonitor<OAuthNegotiateAuthenticationOptions> options,
            [NotNull] ILoggerFactory logger,
            [NotNull] UrlEncoder encoder,
            [NotNull] ISystemClock clock)
            : base(options, logger, encoder, clock)
        {
        }

        protected override String BuildChallengeUrl(AuthenticationProperties properties, String redirectUri)
        {
            return base.BuildChallengeUrl(properties, redirectUri);
        }
        protected override Task HandleChallengeAsync(AuthenticationProperties properties)
        {
            return base.HandleChallengeAsync(properties);
        }
        protected override Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            return base.HandleAuthenticateAsync();
        }
        protected override Task HandleForbiddenAsync(AuthenticationProperties properties)
        {
            return base.HandleForbiddenAsync(properties);
        }
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(OAuthCodeExchangeContext context)
        {
            var result = await  base.ExchangeCodeAsync(context);
            return result;
        }
        protected override void GenerateCorrelationId(AuthenticationProperties properties)
        {
            base.GenerateCorrelationId(properties);
        }
        protected override Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            var result = base.HandleRemoteAuthenticateAsync();
            return result;
        }
        protected override Task<HandleRequestResult> HandleAccessDeniedErrorAsync(AuthenticationProperties properties)
        {
            return base.HandleAccessDeniedErrorAsync(properties);
        }
        protected override Boolean ValidateCorrelationId(AuthenticationProperties properties)
        {
            return base.ValidateCorrelationId(properties);
        }

        /// <inheritdoc />
        protected override async Task<AuthenticationTicket> CreateTicketAsync(
            [NotNull] ClaimsIdentity identity,
            [NotNull] AuthenticationProperties properties,
            [NotNull] OAuthTokenResponse tokens)
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, Options.UserInformationEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", tokens.AccessToken);

            using var response = await Backchannel.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Context.RequestAborted);
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving the user profile.");
            }

            using var payload = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

            var principal = new ClaimsPrincipal(identity);
            var context = new OAuthCreatingTicketContext(principal, properties, Context, Scheme, Options, Backchannel, tokens, payload.RootElement);
            context.RunClaimActions();

            await Options.Events.CreatingTicket(context);
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }
        public override Task<Boolean> ShouldHandleRequestAsync()
        {
            return base.ShouldHandleRequestAsync();
        }
        public override Task<Boolean> HandleRequestAsync()
        {
            var baseresponse = base.HandleRequestAsync();
            return baseresponse;
        }
        protected override String FormatScope()
        {
            return base.FormatScope();
        }
        protected override String FormatScope(IEnumerable<String> scopes)
        {
            return base.FormatScope(scopes);
        }
        protected override Task InitializeHandlerAsync()
        {
            if (Backchannel.BaseAddress == null)
            {
                Backchannel.BaseAddress = new Uri($"{Context.Request.Scheme}://{Context.Request.Host}");// Context.Request;
            }
            return base.InitializeHandlerAsync();
        }
        protected override String ResolveTarget(String scheme)
        {
            return base.ResolveTarget(scheme);
        }
    }
}