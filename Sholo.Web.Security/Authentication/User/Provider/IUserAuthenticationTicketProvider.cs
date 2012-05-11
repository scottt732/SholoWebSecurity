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
using System.Collections.Generic;

namespace Sholo.Web.Security.Authentication.User.Provider
{
    /// <summary>
    /// IUserAuthenticationTicketProvider defines the core contract that a ticket manager must implement in 
    /// order to support the UserAuthenticationTicket features.
    /// </summary>
    public interface IUserAuthenticationTicketProvider : IAuthenticationTicketProvider<string, UserAuthenticationTicket>
    {
        /// <summary>
        /// Revoke all tickets corresponding to the supplied Username.
        /// </summary>
        /// <param name="username">The Username to revoke tickets for</param>
        /// <exception cref="ArgumentNullException">The username supplied is null</exception>
        /// <exception cref="ArgumentException">The username supplied is empty</exception>
        void RevokeUserTickets(string username);

        /// <summary>
        /// Retrieves all non-expired tickets in the ticket store associated with the 
        /// username supplied.
        /// </summary>
        /// <param name="username">The Username to search the collection for</param>
        /// <returns>An enumerable collection of UserAuthenticationTicket</returns>
        /// <exception cref="ArgumentNullException">username is null</exception>
        /// <exception cref="ArgumentException">username is empty</exception>
        IEnumerable<UserAuthenticationTicket> GetUserTickets(string username);

        /// <summary>
        /// Retrieves all non-expired UserAuthenticationTicket keys in the ticket store associated 
        /// with the username supplied.
        /// </summary>
        /// <param name="username">The username to search the collection for</param>
        /// <returns>An enumerable collection of ticket keys</returns>
        /// <exception cref="ArgumentNullException">username is null</exception>
        /// <exception cref="ArgumentException">username is empty</exception>
        IEnumerable<string> GetUserTicketKeys(string username);

        /// <summary>
        /// Retrieves a list of all users that have non-expired ServerAuthenticationTickets.
        /// </summary>
        /// <returns>An enumerable collection of Username's</returns>
        IEnumerable<string> GetAllTicketedUsers();
    }
}
