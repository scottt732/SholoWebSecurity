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