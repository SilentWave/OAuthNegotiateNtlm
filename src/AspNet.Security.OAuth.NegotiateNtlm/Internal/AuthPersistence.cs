using System;

namespace AspNet.Security.OAuth.NegotiateNtlm
{
    // This allows us to have one disposal registration per connection and limits churn on the Items collection.
    class AuthPersistence : IDisposable
    {
        internal INegotiateState State { get; set; }

        public void Dispose()
        {
            State?.Dispose();
        }
    }
}