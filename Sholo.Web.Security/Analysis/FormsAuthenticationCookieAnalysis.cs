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
using System.Web;
using System.Web.Security;

namespace Sholo.Web.Security.Analysis
{
    /// <summary>
    /// Analysis results of the FormsAuthenticationCookie validity & security
    /// </summary>
    [Serializable]
    public sealed class FormsAuthenticationCookieAnalysis
    {
        private FormsAuthenticationTicket _formsAuthenticationTicket;

        /// <summary>
        /// The FormsAuthenticationCookie to validate
        /// </summary>
        public HttpCookie FormsAuthenticationCookie { get; internal set; }

        /// <summary>
        /// Inidicates whether or not a FormsAuthenticationCookie was present in the current request
        /// </summary>
        public bool CookieExists { get; internal set; }
            
        /// <summary>
        /// Indicates whether the FormsAuthenticationCookie is valid
        /// </summary>
        public bool IsValid { get; internal set; }
            
        /// <summary>
        /// Indicates whether the FormsAuthenticationCookie is malicious
        /// </summary>
        public bool IsMalicious { get; internal set; }

        /// <summary>
        /// Indicates whether the expected FormsAuthenticationCookie cookie is an actual FormsAuthenticationCookie
        /// </summary>
        public bool IsCookieFormsAuthCookie { get; internal set; }
            
        /// <summary>
        /// Indicates whether the cookie domain is valid & matches the configured value
        /// </summary>
        public bool IsDomainValid { get; internal set; }
            
        /// <summary>
        /// Indicates whether the FormsAuthenticationCookie is expired
        /// </summary>
        public bool IsExpired { get; internal set; }
            
        /// <summary>
        /// Inidicates whether the CookiePath in the FormsAuthenticationCookie is valid & matches the configured value
        /// </summary>
        public bool IsPathValid { get; internal set; }
            
        /// <summary>
        /// Indicates whether the Secure property of the FormsAuthenticationCookie is valid & matches the configured value
        /// </summary>
        public bool IsSecureValid { get; internal set; }
            
        /// <summary>
        /// Indicates whether the cookie has a value
        /// </summary>
        public bool HasValue { get; internal set; }
            
        /// <summary>
        /// Indicates whether the cookie decrypts successfully
        /// </summary>
        public bool ValueDecrypts { get; internal set; }

        /// <summary>
        /// Retrieves the FormsAuthenticationTicket contained within the FormsAuthenticationCookie
        /// </summary>
        /// <returns>The FormsAuthenticationTicket contained within the FormsAuthenticationCookie</returns>
        public FormsAuthenticationTicket GetFormsAuthenticationTicket()
        {
            return _formsAuthenticationTicket;
        }

        internal void SetFormsAuthenticationTicket(FormsAuthenticationTicket ticket)
        {
            _formsAuthenticationTicket = ticket;
        }
    }
}