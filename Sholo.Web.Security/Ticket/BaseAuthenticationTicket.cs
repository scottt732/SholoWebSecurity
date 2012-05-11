/*
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

namespace Sholo.Web.Security.Ticket
{
    /// <summary>
    /// Base class for an IAuthenticationTicketProvider implementation
    /// </summary>
    public abstract class BaseAuthenticationTicket : IAuthenticationTicket
    {
        /// <summary>
        /// A GUID serving as the primary key in the Provider
        /// </summary>
        public string Key { get; set; }

        /// <summary>
        /// The name of the FormsAuthenticationCookie
        /// </summary>
        public string CookieName { get; set; }

        /// <summary>
        /// The domain on the FormsAuthenticationCookie
        /// </summary>
        public string CookieDomain { get; set; }

        /// <summary>
        /// The path on the server for which the FormsAuthenticationCookie is applicable.
        /// </summary>
        public string CookiePath { get; set; }

        /// <summary>
        /// Whether or not the FormsAuthenticationCookie requires HTTPS
        /// </summary>
        public bool CookieSecure { get; set; }

        /// <summary>
        /// The expiration date of the FormsAuthenticationTicket
        /// </summary>
        public DateTime TicketExpiration { get; set; }

        /// <summary>
        /// Whether or not the FormsAuthenticationTicket is allowed to 
        /// persist across browser sessions.
        /// </summary>
        public bool TicketIsPersistent { get; set; }

        /// <summary>
        /// The date and time at which the FormsAuthenticationTicket was
        /// issued.
        /// </summary>
        public DateTime TicketIssueDate { get; set; }

        /// <summary>
        /// The UserData field originally contained in the FormsAuthenticationTicket.
        /// Unlike the other properties which are copied here, the original UserData 
        /// contained in the FormsAuthenticationTicket is moved here to make room for 
        /// the hash of the FormsAuthenticationTicket's properties and and GUID
        /// corresponding to the Key in this data structure.
        /// </summary>
        public string TicketUserData { get; set; }

        /// <summary>
        /// The FormsAuthenticationTicket version (always expected to be 2 for 
        /// ASP.NET 2.0-4.0)
        /// </summary>
        public int TicketVersion { get; set; }

        /// <summary>
        /// The hash of the FormsAuthenticationTicket's properties concatenated
        /// with a salt string.
        /// </summary>
        public string TicketHash { get; set; }

        /// <summary>
        /// Readonly property which indicates whether or not the ValidUntilDate is in
        /// the past (i.e., the ticket is expired).  IsExpired tickets should/will be 
        /// purged from the Provider during the RemoveExpiredTickets() call,
        /// during the BeginRequest event handler.
        /// </summary>
        public bool TicketExpired
        {
            get
            {
                return (DateTime.Now.CompareTo(TicketExpiration) > 0);
            }
        }
    }
}
