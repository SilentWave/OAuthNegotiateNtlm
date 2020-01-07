using System;
using System.Security.Principal;

namespace AspNet.Security.OAuth.NegotiateNtlm
{
    // For testing
    internal interface INegotiateState : IDisposable
    {
        string GetOutgoingBlob(string incomingBlob, out BlobErrorType status, out Exception error);

        bool IsCompleted { get; }

        string Protocol { get; }

        IIdentity GetIdentity();
    }

    internal enum BlobErrorType
    {
        None,
        CredentialError,
        ClientError,
        Other
    }
}