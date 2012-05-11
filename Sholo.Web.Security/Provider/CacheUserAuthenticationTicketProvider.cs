﻿/*
 * Copyright 2010-2012, Scott Holodak
 * 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Web;
using System.Web.Caching;
using Sholo.Web.Security.Ticket;

namespace Sholo.Web.Security.Provider
{
    /// <summary>
    /// An IUserAuthenticationTicketProvider implementation that relies on the ASP.NET Caching model for ticket 
    /// storage.  Generally this implies that the ticket storage is maintained locally on the web
    /// server (either in memory or on disk).  A limitation of this model is that it will not 
    /// support clustered, load balanced, or round-robin style configurations.
    /// </summary>
    public sealed class CacheUserAuthenticationTicketProvider : UserAuthenticationTicketProviderBase
    {
        /// <summary>
        /// This prefix is prepended to ticket key as the key to the cache.
        /// </summary>
        private const string UserTicketKeyPrefix = "USER::";

        /// <summary>
        /// Initializes the CacheUserAuthenticationTicketProvider module.
        /// </summary>
        public override void Initialize(string name, NameValueCollection config)
        {
            if (config == null)
            {
                throw new ArgumentNullException("config");
            } 
            
            if (string.IsNullOrEmpty(name)) 
            {
                name = "CacheUserAuthenticationTicketProvider";      
            }

            if (string.IsNullOrEmpty (config["description"]))
            {
                config.Remove("description");
                config.Add("description", "Cache-based user authentication provider");
            } 

            base.Initialize(name, config);
        }

        /// <summary>
        /// Removes expired entries from the ticket store
        /// </summary>
        public override void RemoveExpiredTickets()
        {
            // No-op.  ASP.NET Cache provider removes expired entries automatically.
        }

        /// <summary>
        /// Retrieve a UserAuthenticationTicket from the ticket store 
        /// by it's ticket key
        /// </summary>
        /// <param name="userAuthenticationTicketKey">The ticket key generated by the server</param>
        /// <returns>The UserAuthenticationTicket or null if no matching ticket is found</returns>
        /// <exception cref="ArgumentNullException">userAuthenticationTicketKey is null</exception>
        /// <exception cref="ArgumentException">userAuthenticationTicketKey is empty</exception>
        public override UserAuthenticationTicket GetTicket(string userAuthenticationTicketKey)
        {
            if (userAuthenticationTicketKey == null)
            {
                throw new ArgumentNullException("userAuthenticationTicketKey", "userAuthenticationTicketKey parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(userAuthenticationTicketKey))
            {
                throw new ArgumentException("userAuthenticationTicketKey parameter cannot be null or empty.", "userAuthenticationTicketKey");
            }                

            string key = GetCacheKey(userAuthenticationTicketKey);
            if (HttpContext.Current.Cache[key] != null)
            {
                UserAuthenticationTicket result = HttpContext.Current.Cache[key] as UserAuthenticationTicket;
                return result;
            }
            return null;
        }

        /// <summary>
        /// Inserts a UserAuthenticationTicket to the ticket store with a corresponding 
        /// ticket expiration date.
        /// </summary>
        /// <param name="ticket">The UserAuthenticationTicket to insert</param>
        /// <param name="expiration">The date and time at which the ticket expires</param>
        /// <exception cref="ArgumentNullException">UserAuthenticationTicket is null</exception>
        public override void InsertTicket(UserAuthenticationTicket ticket, DateTime expiration)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket", "UserAuthenticationTicket parameter cannot be null.");
            }

            // Don't enforce sliding expiration on the cache entry.  Sliding expiration 
            // is handled by the HttpModule
            HttpContext.Current.Cache.Insert(GetCacheKey(ticket.Key), ticket, null, expiration, Cache.NoSlidingExpiration);
        }

        /// <summary>
        /// Updates the expiration date and time for an existing ticket.  If the ticket does
        /// not exist in the ticket store, just return (do not throw an exception).
        /// </summary>
        /// <param name="ticket">The UserAuthenticationTicket to insert</param>
        /// <param name="newExpiration">The new expiration date and time</param>
        /// <exception cref="ArgumentNullException">UserAuthenticationTicket is null</exception>
        public override void UpdateTicketExpiration(UserAuthenticationTicket ticket, DateTime newExpiration)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket", "UserAuthenticationTicket parameter cannot be null.");
            }

            RevokeTicket(ticket.Key);
            InsertTicket(ticket, newExpiration);
        }

        /// <summary>
        /// Removes the ticket from the collection if it exists.  If the ticket does not
        /// exist in the ticket store, just return (do not throw an exception).
        /// </summary>
        /// <param name="userAuthenticationTicketKey">The ticket to remove from the ticket store</param>
        /// <exception cref="ArgumentNullException">userAuthenticationTicketKey is null</exception>
        /// <exception cref="ArgumentException">userAuthenticationTicketKey is empty</exception>
        public override void RevokeTicket(string userAuthenticationTicketKey)
        {
            if (userAuthenticationTicketKey == null)
            {
                throw new ArgumentNullException("userAuthenticationTicketKey", "userAuthenticationTicketKey parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(userAuthenticationTicketKey))
            {
                throw new ArgumentException("userAuthenticationTicketKey parameter cannot be null or empty.", "userAuthenticationTicketKey");
            }

            string key = GetCacheKey(userAuthenticationTicketKey);
            if (HttpContext.Current.Cache[key] != null)
            {
                UserAuthenticationTicket ticket = HttpContext.Current.Cache[key] as UserAuthenticationTicket;
                if (ticket != null)
                {
                    if (HttpContext.Current.Cache[key] != null)
                    {
                        HttpContext.Current.Cache.Remove(key);
                    }
                }
            }
        }

        /// <summary>
        /// Indicates whether or not the ticket store contains the supplied userAuthenticationTicketKey
        /// </summary>
        /// <param name="userAuthenticationTicketKey">The ticket to check for</param>
        /// <returns>True if the ticket is contained in the store</returns>
        /// <exception cref="ArgumentNullException">userAuthenticationTicketKey is null</exception>
        /// <exception cref="ArgumentException">userAuthenticationTicketKey is empty</exception>
        public override bool ContainsTicket(string userAuthenticationTicketKey)
        {
            if (userAuthenticationTicketKey == null)
            {
                throw new ArgumentNullException("userAuthenticationTicketKey", "userAuthenticationTicketKey parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(userAuthenticationTicketKey))
            {
                throw new ArgumentException("userAuthenticationTicketKey parameter cannot be null or empty.", "userAuthenticationTicketKey");
            }

            IDictionaryEnumerator enumerator = HttpContext.Current.Cache.GetEnumerator();
            while (enumerator.MoveNext())
            {
                string currentKey = enumerator.Entry.Key as string;
                if (currentKey != null && currentKey.StartsWith(UserTicketKeyPrefix))
                {
                    UserAuthenticationTicket currentAuthTicket = enumerator.Entry.Value as UserAuthenticationTicket;
                    if (currentAuthTicket != null)
                    {
                        if (currentAuthTicket.Key == userAuthenticationTicketKey)
                        {
                            return true;
                        }
                    }
                }
            }
            return false;
        }

        /// <summary>
        /// Revoke all tickets corresponding to the supplied Username.
        /// </summary>
        /// <param name="username">The Username to revoke tickets for</param>
        /// <exception cref="ArgumentNullException">The username supplied is null</exception>
        /// <exception cref="ArgumentException">The username supplied is empty</exception>
        public override void RevokeUserTickets(string username)
        {
            if (username == null)
            {
                throw new ArgumentNullException("username", "username parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username parameter cannot be null or empty.", "username");
            }

            IEnumerable<UserAuthenticationTicket> allTickets = GetAllTickets();
            foreach (UserAuthenticationTicket ticket in allTickets)
            {
                if (string.Compare(ticket.Username, username, StringComparison.OrdinalIgnoreCase) == 0)
                {
                    RevokeTicket(ticket.Key);
                }
            }
        }

        /// <summary>
        /// Retrieves all tickets in the ticket store that have not already expired.
        /// </summary>
        /// <returns>An enumerable collection of UserAuthenticationTickets</returns>
        public override IEnumerable<UserAuthenticationTicket> GetAllTickets()
        {
            IDictionaryEnumerator enumerator = HttpContext.Current.Cache.GetEnumerator();
            while (enumerator.MoveNext())
            {
                string currentKey = enumerator.Entry.Key as string;
                if (currentKey != null && currentKey.StartsWith(UserTicketKeyPrefix))
                {
                    UserAuthenticationTicket currentTicket = enumerator.Entry.Value as UserAuthenticationTicket;
                    if (currentTicket != null)
                    {
                        yield return currentTicket;
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves all non-expired tickets in the ticket store associated with the 
        /// username supplied.
        /// </summary>
        /// <param name="username">The Username to search the collection for</param>
        /// <returns>An enumerable collection of ServerAuthenticationTickets</returns>
        /// <exception cref="ArgumentNullException">username is null</exception>
        /// <exception cref="ArgumentException">username is empty</exception>
        public override IEnumerable<UserAuthenticationTicket> GetUserTickets(string username)
        {
            if (username == null)
            {
                throw new ArgumentNullException("username", "username parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username parameter cannot be null or empty.", "username");
            }

            IDictionaryEnumerator enumerator = HttpContext.Current.Cache.GetEnumerator();
            while (enumerator.MoveNext())
            {
                string currentKey = enumerator.Entry.Key as string;
                if (currentKey != null && currentKey.StartsWith(UserTicketKeyPrefix))
                {
                    UserAuthenticationTicket currentTicket = enumerator.Entry.Value as UserAuthenticationTicket;
                    if (currentTicket != null && string.Compare(currentTicket.Username, username, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        yield return currentTicket;
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves all UserAuthenticationTicket keys in the ticket store that have not already
        /// expired.
        /// </summary>
        /// <returns>An enumerable collection of tickets</returns>
        public override IEnumerable<string> GetAllTicketKeys()
        {
            IDictionaryEnumerator enumerator = HttpContext.Current.Cache.GetEnumerator();
            while (enumerator.MoveNext())
            {
                string currentKey = enumerator.Entry.Key as string;
                if (currentKey != null && currentKey.StartsWith(UserTicketKeyPrefix))
                {
                    UserAuthenticationTicket currentAuthTicket = enumerator.Entry.Value as UserAuthenticationTicket;
                    if (currentAuthTicket != null)
                    {
                        yield return currentAuthTicket.Key;
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves all non-expired UserAuthenticationTicket keys in the ticket store associated 
        /// with the username supplied.
        /// </summary>
        /// <param name="username">The username to search the collection for</param>
        /// <returns>An enumerable collection of tickets</returns>
        /// <exception cref="ArgumentNullException">username is null</exception>
        /// <exception cref="ArgumentException">username is empty</exception>
        public override IEnumerable<string> GetUserTicketKeys(string username)
        {
            if (username == null)
            {
                throw new ArgumentNullException("username", "username parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username parameter cannot be null or empty.", "username");
            }

            IDictionaryEnumerator enumerator = HttpContext.Current.Cache.GetEnumerator();
            while (enumerator.MoveNext())
            {
                string currentKey = enumerator.Entry.Key as string;
                if (currentKey != null && currentKey.StartsWith(UserTicketKeyPrefix))
                {
                    UserAuthenticationTicket currentAuthTicket = enumerator.Entry.Value as UserAuthenticationTicket;
                    if (currentAuthTicket != null && string.Compare(currentAuthTicket.Username, username, StringComparison.OrdinalIgnoreCase) == 0)
                    {
                        yield return currentAuthTicket.Key;
                    }
                }
            }
        }

        /// <summary>
        /// Retrieves a list of all users that have non-expired ServerAuthenticationTickets.
        /// </summary>
        /// <returns>An enumerable collection of Username's</returns>
        public override IEnumerable<string> GetAllTicketedUsers()
        {
            List<string> result = new List<string>();
            IEnumerable<UserAuthenticationTicket> tickets = GetAllTickets();
            foreach (UserAuthenticationTicket ticket in tickets)
            {
                if (!result.Contains(ticket.Username))
                {
                    result.Add(ticket.Username);
                }
            }
            return result.ToArray();
        }

        /// <summary>
        /// Verify that the supplied UserAuthenticationTicket exists in the ticket store
        /// </summary>
        /// <param name="ticket">The UserAuthenticationTicket to verify</param>
        /// <returns>
        /// True if the ticket exists in the ticket store and the properties of that 
        /// ticket match the properties of the ticket in the ticket store.
        /// </returns>
        public override bool VerifyTicket(UserAuthenticationTicket ticket)
        {
            if (ticket == null)
            {
                throw new ArgumentNullException("ticket", "UserAuthenticationTicket parameter cannot be null.");
            }

            string incomingTicket = ticket.Key;
            UserAuthenticationTicket cacheAuthTicket = GetTicket(incomingTicket);
            if (cacheAuthTicket != null)
            {
                string cacheTicket = cacheAuthTicket.Key;
                if (cacheTicket == incomingTicket)
                {
                    if (string.Compare(cacheAuthTicket.Username, ticket.Username, StringComparison.OrdinalIgnoreCase) != 0)
                    {
                        return false;
                    }

                    return true;
                }
            }
            else
            {
                return false;
            }
            return false;
        }

        /// <summary>
        /// Converts a ticketKey to a corresponding key in the ticket store (cache provider). 
        /// </summary>
        /// <param name="ticketKey">The ticketKey to convert.</param>
        /// <returns>The cache key associated with the ticketKey</returns>
        /// <exception cref="ArgumentNullException">ticketKey is null</exception>
        /// <exception cref="ArgumentException">ticketKey is empty</exception>
        private static string GetCacheKey(string ticketKey)
        {
            if (ticketKey == null)
            {
                throw new ArgumentNullException("ticketKey", "ticketKey parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(ticketKey))
            {
                throw new ArgumentException("ticketKey parameter cannot be null or empty.", "ticketKey");
            }

            return UserTicketKeyPrefix + ticketKey;
        }
    }
}
