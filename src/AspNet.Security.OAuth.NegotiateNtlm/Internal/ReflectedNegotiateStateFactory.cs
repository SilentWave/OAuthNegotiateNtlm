using System;
using System.Collections.Generic;
using System.Text;

namespace AspNet.Security.OAuth.NegotiateNtlm
{
    internal class ReflectedNegotiateStateFactory : INegotiateStateFactory
    {
        public INegotiateState CreateInstance()
        {
            return new ReflectedNegotiateState();
        }
    }
}