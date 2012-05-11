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

using System;
using System.Diagnostics;
using System.Security.Principal;
using System.Threading;
using System.Web;

namespace Sholo.Web.Security.Analysis
{
    /// <summary>
    /// Context information derived from the current request
    /// </summary>
    [Serializable]
    public sealed class ContextInformation
    {
        /// <summary>
        /// ContextInformation constructor
        /// </summary>
        public ContextInformation()
        {
            HttpContext context = HttpContext.Current;
            HttpRequest request = context.Request;
            IPrincipal contextUser = context.User;
            IIdentity contextIdentity = (contextUser != null ? contextUser.Identity : null);
            IPrincipal threadUser = Thread.CurrentPrincipal;
            IIdentity threadIdentity = (threadUser != null ? threadUser.Identity : null);

            HostAddress = request.UserHostAddress;
            UserAgent = request.UserAgent;

            bool userIdentityIsAuthenticated = (contextIdentity != null && contextIdentity.IsAuthenticated);
            string userIdentityName = (contextIdentity != null ? contextIdentity.Name : null);
            bool threadCurrentPrincipalIdentityIsAuthenticated = (threadIdentity != null && threadIdentity.IsAuthenticated);
            string threadCurrentPrincipalIdentityName = (threadIdentity != null ? threadIdentity.Name : null);

            Debug.Assert(threadCurrentPrincipalIdentityIsAuthenticated == userIdentityIsAuthenticated);
            Debug.Assert((String.IsNullOrEmpty(userIdentityName) && String.IsNullOrEmpty(threadCurrentPrincipalIdentityName)) || userIdentityName == threadCurrentPrincipalIdentityName);

            IsAuthenticated = userIdentityIsAuthenticated;
            UserName = userIdentityName;
        }

        /// <summary>
        /// The User-Agent passed from the client
        /// </summary>
        public string UserAgent { get; set; }

        /// <summary>
        /// The host address of the client
        /// </summary>
        public string HostAddress { get; internal set; }
            
        /// <summary>
        /// Indicates whether or not the current request is authenticated
        /// </summary>
        public bool IsAuthenticated { get; internal set; }
            
        /// <summary>
        /// The username associated with the current request
        /// </summary>
        public string UserName { get; internal set; }
    }
}