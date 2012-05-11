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

namespace Sholo.Web.Security.Analysis
{
    ///<summary>
    /// The status of the FormsAuthenticationTicket's relating to presence 
    /// and/or validation.  This is used to determine what FormsAuthentication-
    /// related action occurred during the processing of the current request.
    ///</summary>
    public enum FormsAuthenticationStatus
    {
        /// <summary>
        /// A FormsAuthenticationCookie and/or FormsAuthenticationTicket was 
        /// not found in the current Request's Cookies collection.
        /// </summary>
        NotFound,
            
        /// <summary>
        /// A FormsAuthenticationCookie and FormsAuthenticationTicket were found 
        /// in the current Request's Cookies collection but one of the following 
        /// problems was identified:
        /// <list>
        ///     <item>
        ///         The FormsAuthenticationTicket's properties failed the 
        ///         hash validation
        ///     </item>
        ///     <item>
        ///         The FormsAuthenticationTicket does not have a corresponding 
        ///         UserAuthenticationTicket in the Provider.  This could be
        ///         because the ticket has expired on the server, was explicitly
        ///         revoked, or was maliciously crafted by an attacker.
        ///     </item>
        ///     <item>
        ///         The FormsAuthenticationCookie and/or the FormsAuthenticationTicket
        ///         contained in it do not match the UserAuthenticationTicket in
        ///         in the Provider.  This generally indicates that the ticket
        ///         has been tampered with.
        ///     </item>
        /// </list>
        /// </summary>
        Invalid,

        /// <summary>
        /// A FormsAuthenticationCookie and FormsAuthenticationTicket were found
        /// and validated against the UserAuthenticationTicket record stored on 
        /// the server.
        /// </summary>
        Valid
    }
}