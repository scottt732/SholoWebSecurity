/*
 * Copyright 2010-2012, Scott Holodak, Alex Friedman
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

namespace Sholo.Web.Security.Authentication.User
{
    ///<summary>
    /// A data object containing information about 
    /// FormsAuthenticationCookies, FormsAuthenticationTickets,
    /// and the IP address of the client that requested them.  This
    /// is used for the stateful validation of incoming requests.
    ///</summary>
    public class UserAuthenticationTicket : BaseAuthenticationTicket
    {
        /// <summary>
        /// The username to be authenticated by the FormsAuthenticationTicket
        /// </summary>
        public string Username { get; set; }

        /// <summary>
        /// The HostAddress of the client who initially received the
        /// FormsAuthenticationTicket
        /// </summary>
        public string HostAddress { get; set; }

        /// <summary>
        /// The UserAgent of the browser who initially received the
        /// FormsAuthenticationTicket
        /// </summary>
        public string UserAgent { get; set; }
    }
}