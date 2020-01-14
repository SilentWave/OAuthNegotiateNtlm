using Microsoft.AspNetCore.Connections.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;
using System.Threading.Tasks;

namespace AspNet.Security.OAuth.NegotiateNtlm.Controllers
{
    public class Negotiate : Controller
    {

        static Utils.TimedDictionary<String, object> ShortLivedPersistence = new Utils.TimedDictionary<String, object>(TimeSpan.FromMinutes(1));
        static Utils.TimedDictionary<String, object> LongLivedPersistence = new Utils.TimedDictionary<String, object>(TimeSpan.FromDays(7));

        private readonly IOptionsMonitor<OAuthNegotiateAuthenticationOptions> _options;
        private OAuthNegotiateAuthenticationOptions Options => _options.CurrentValue;

        public Negotiate(IOptionsMonitor<OAuthNegotiateAuthenticationOptions> options)
        {
            _options = options ?? throw new ArgumentNullException(nameof(options));
        }

        public IActionResult Callback()
        {
            return Ok();
        }

        private String GetKey(ConnectionInfo ci) => ci.Id + "_" + NegotiateAuthenticationDefaults.AuthPersistenceKey;

        /// <summary>
        /// Browser won't send authorization header automatically.
        /// first we have to challenge it with an un-authorized response
        /// and a header www-authenticate
        /// </summary>
        /// <returns></returns>
        public IActionResult ChallengeBrowser()
        {
            AuthPersistence persistence = null;

            if (ShortLivedPersistence.TryGetValue(GetKey(HttpContext.Connection), out var temp))
            {
                persistence = temp as AuthPersistence;
            }
            var _negotiateState = persistence?.State;

            var authorizationHeader = Request.Headers[HeaderNames.Authorization];

            if (StringValues.IsNullOrEmpty(authorizationHeader))
            {
                if (_negotiateState?.IsCompleted == false)
                {
                    ShortLivedPersistence.TryRemove(GetKey(HttpContext.Connection), out _);
                    return BadRequest("An anonymous request was received in between authentication handshake requests.");
                }
                Response.Headers.Append(HeaderNames.WWWAuthenticate, NegotiateAuthenticationDefaults.AuthHeaderPrefix);
                return Unauthorized();
            }

            var authorization = authorizationHeader.ToString();
            string token = null;
            if (authorization.StartsWith(NegotiateAuthenticationDefaults.AuthHeaderPrefix, StringComparison.OrdinalIgnoreCase))
            {
                token = authorization.Substring(NegotiateAuthenticationDefaults.AuthHeaderPrefix.Length).Trim();
            }
            else
            {
                if (_negotiateState?.IsCompleted == false)
                {
                    ShortLivedPersistence.TryRemove(GetKey(HttpContext.Connection), out _);
                    return BadRequest("Non-negotiate request was received in between authentication handshake requests.");
                }
                return Unauthorized();
            }

            // WinHttpHandler re-authenticates an existing connection if it gets another challenge on subsequent requests.
            if (_negotiateState?.IsCompleted == true)
            {
                //Logger.Reauthenticating();
                _negotiateState.Dispose();
                _negotiateState = null;
                persistence.State = null;
            }

            _negotiateState ??= Options.StateFactory.CreateInstance();

            var outgoing = _negotiateState.GetOutgoingBlob(token, out var errorType, out var exception);
            //Logger.LogInformation(errorType.ToString());
            if (errorType != BlobErrorType.None)
            {
                _negotiateState.Dispose();
                _negotiateState = null;
                if (persistence?.State != null)
                {
                    persistence.State.Dispose();
                    persistence.State = null;
                }

                if (errorType == BlobErrorType.CredentialError)
                {
                    //Logger.CredentialError(exception);
                    //authFailedEventCalled = true; // Could throw, and we don't want to double trigger the event.
                    //var result = await InvokeAuthenticateFailedEvent(exception);
                    //return result ?? false; // Default to skipping the handler, let AuthZ generate a new 401
                    return Unauthorized();
                }
                else if (errorType == BlobErrorType.ClientError)
                {
                    //Logger.ClientError(exception);
                    //authFailedEventCalled = true; // Could throw, and we don't want to double trigger the event.
                    //var result = await InvokeAuthenticateFailedEvent(exception);
                    //if (result.HasValue)
                    //{
                    //    return result.Value;
                    //}
                    ShortLivedPersistence.TryRemove(GetKey(HttpContext.Connection), out _);
                    return BadRequest("Client error"); // Default to terminating request
                }

                throw exception;
            }

            if (!_negotiateState.IsCompleted)
            {
                persistence ??= EstablishConnectionPersistence(HttpContext.Connection, ShortLivedPersistence);
                // Save the state long enough to complete the multi-stage handshake.
                // We'll remove it once complete if !PersistNtlm/KerberosCredentials.
                persistence.State = _negotiateState;

                //Logger.IncompleteNegotiateChallenge();
                Response.Headers.Append(HeaderNames.WWWAuthenticate, NegotiateAuthenticationDefaults.AuthHeaderPrefix + outgoing);
                return Unauthorized();
            }

            //Logger.NegotiateComplete();

            // There can be a final blob of data we need to send to the client, but let the request execute as normal.
            if (!string.IsNullOrEmpty(outgoing))
            {
                Response.OnStarting(() =>
                {
                        // Only include it if the response ultimately succeeds. This avoids adding it twice if Challenge is called again.
                        if (Response.StatusCode < StatusCodes.Status400BadRequest)
                    {
                        Response.Headers.Append(HeaderNames.WWWAuthenticate, NegotiateAuthenticationDefaults.AuthHeaderPrefix + outgoing);
                    }
                    return Task.CompletedTask;
                });
            }

            // Deal with connection credential persistence.

            if (_negotiateState.Protocol == "NTLM" && !Options.PersistNtlmCredentials)
            {
                // NTLM was already put in the persitence cache on the prior request so we could complete the handshake.
                // Take it out if we don't want it to persist.
                Debug.Assert(object.ReferenceEquals(persistence?.State, _negotiateState),
                    "NTLM is a two stage process, it must have already been in the cache for the handshake to succeed.");
                //Logger.DisablingCredentialPersistence(_negotiateState.Protocol);
                persistence.State = null;
                Response.RegisterForDispose(_negotiateState);
            }
            else if (_negotiateState.Protocol == "Kerberos")
            {
                // Kerberos can require one or two stage handshakes
                if (Options.PersistKerberosCredentials)
                {
                    //Logger.EnablingCredentialPersistence();
                    persistence ??= EstablishConnectionPersistence(HttpContext.Connection, ShortLivedPersistence);
                    persistence.State = _negotiateState;
                }
                else
                {
                    if (persistence?.State != null)
                    {
                        //Logger.DisablingCredentialPersistence(_negotiateState.Protocol);
                        persistence.State = null;
                    }
                    Response.RegisterForDispose(_negotiateState);
                }
            }

            // Note we run the Authenticated event in HandleAuthenticateAsync so it is per-request rather than per connection.

            persistence?.Dispose();

            // Make a new copy of the user for each request, they are mutable objects and
            // things like ClaimsTransformation run per request.
            var identity = _negotiateState.GetIdentity();
            ClaimsPrincipal principal;
            if (identity is WindowsIdentity winIdentity)
            {
                principal = new WindowsPrincipal(winIdentity);
                Response.RegisterForDispose(winIdentity);
            }
            else
            {
                principal = new ClaimsPrincipal(new ClaimsIdentity(identity));
            }

            var code = Guid.NewGuid();
            {
                var added = ShortLivedPersistence.TryAdd(
                  code.ToString(),
                  new UserInformation
                  {
                      Sub = principal.Claims.SingleOrDefault(x => x.Type == ClaimTypes.WindowsSubAuthority)?.Value ?? principal.Claims.SingleOrDefault(x => x.Type == ClaimTypes.PrimarySid)?.Value,
                      Name = principal.Identity.Name,
                      GivenName = principal.Claims.SingleOrDefault(x => x.Type == ClaimTypes.GivenName)?.Value,
                      FamilyName = principal.Claims.SingleOrDefault(x => x.Type == ClaimTypes.Surname)?.Value,
                      Email = principal.Claims.SingleOrDefault(x => x.Type == ClaimTypes.Email)?.Value
                  });
                if (!added)
                {
                    // this is not probable
                    throw new InvalidOperationException("another key for this code already existed");
                }
            }

            var redirectUri = HttpContext.Request.Query["redirect_uri"];
            var responseType = HttpContext.Request.Query["response_type"];
            var scope = HttpContext.Request.Query["scope"];
            var state = HttpContext.Request.Query["state"];
            return Redirect($"{redirectUri}?state={state}&scope={scope}&response_type={responseType}&code={code}");


        }

        public IActionResult UserInformation()
        {
            if (!Request.Headers.ContainsKey(HeaderNames.Authorization)) { return Unauthorized(); }
            var splitted = Request.Headers[HeaderNames.Authorization][0].Split(' ');
            var tokenKind = splitted.First();
            var token = splitted.Last();
            if (LongLivedPersistence.TryGetValue(token, out var temp))
            {
                var userinfo = temp as UserInformation;
                return Ok(userinfo);
            }
            return BadRequest("The requested token is invalid");
        }

        [HttpPost]
        public IActionResult Token()
        {
            var code = Request.Form["code"];
            if (!ShortLivedPersistence.ContainsKey(code)) return BadRequest();

            if (!ShortLivedPersistence.TryRemove(code, out var userInfo))
            {
                return BadRequest("the requested code is invalid");
            }

            var access = Guid.NewGuid().ToString();
            LongLivedPersistence.TryAdd(access, userInfo);
            var result = new Token() { Id = code, Kind = TokenKind.bearer, Scope = "openid email profile", Access = access, ExpiresIn = 3600 };
            return Ok(result);
        }

        private AuthPersistence EstablishConnectionPersistence(ConnectionInfo ci, Utils.TimedDictionary<String, object> items)
        {
            var persistence = new AuthPersistence();
            Debug.Assert(items.TryAdd(GetKey(ci), persistence), "This should only be registered once per connection");
            return persistence;
        }

        private static Task DisposeState(object state)
        {
            ((IDisposable)state).Dispose();
            return Task.CompletedTask;
        }

        public IActionResult Error()
        {
            return View();
        }
    }
}
