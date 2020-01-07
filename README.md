# OAuthNegotiateNtlm
A local negotiate ntlm oauth provider


This repository is an experimental Oauth provider that also add local controllers that triggers the negotiate/ntlm authentication and behave like an oauth server.

The intent is to have a lightweight alternative that fit between an external OAuth server like identityServer4 that can already do something like this, or even better, and the negotiate/ntlm authentication provided by the asp.net core team.

Some code come from those public repositories: 

https://github.com/aspnet-contrib/AspNet.Security.OAuth.Providers/tree/dev/src/AspNet.Security.OAuth.Amazon

https://github.com/aspnet/AspNetCore/tree/fece4705eec5b2a118d9bd8b68eb867d2f573f7c/src/Security/Authentication/Negotiate/src
