using System;
using System.Collections;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Text;
using System.Threading;

namespace AspNet.Security.OAuth.NegotiateNtlm.Utils
{
    class TimedDictionary<TKey, TValue> where TKey : notnull
    {
        private readonly ConcurrentDictionary<TKey, (Timer Timer, TValue Value)> _underlyingDictionary = new ConcurrentDictionary<TKey, (Timer, TValue)>();
       
        public TimeSpan RemoveAfter { get; }

        public TimedDictionary(TimeSpan removeAfter)
        {
            RemoveAfter = removeAfter;
        }

        private Timer Timerfactory(TKey key) => new Timer(HandleTimer, key, RemoveAfter, Timeout.InfiniteTimeSpan);
        
        private void HandleTimer(Object state)
        {
            var key = (TKey)state;
            _ = TryRemove(key, out _);
        }

        public Boolean TryRemove(TKey key, out TValue value)
        {
            var returnVal = _underlyingDictionary.TryRemove(key, out var tuple);
            value = default;
            if (returnVal)
            {
                tuple.Timer.Dispose();
                value = tuple.Value;
            }
            return returnVal;
        }

        public TValue GetOrAdd(TKey key, Func<TKey, TValue> valueFactory)
        {
            var underlyingValue = _underlyingDictionary.GetOrAdd(key, k =>
            {
                var value = valueFactory(k);
                var timer = Timerfactory(k);
                return (timer, value);
            });
            return underlyingValue.Value;
        }

        public Boolean ContainsKey(TKey key) => _underlyingDictionary.ContainsKey(key);

        public Boolean TryGetValue(TKey key, out TValue value)
        {
            value = default;
            var result = _underlyingDictionary.TryGetValue(key, out var tuple);
            if (result)
            {
                value = tuple.Value;
            }
            return result;
        }

        public Boolean TryAdd(TKey key, TValue value) =>  _underlyingDictionary.TryAdd(key, (Timerfactory(key), value));
    }
}
