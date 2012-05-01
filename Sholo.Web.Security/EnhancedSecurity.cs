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
using System.Configuration;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Text;
using System.Threading;
using System.Web;
using System.Web.Configuration;
using System.Web.Security;
using Sholo.Web.Security.Configuration;
using Sholo.Web.Security.Provider;
using Sholo.Web.Security.State;

namespace Sholo.Web.Security
{
    /// <summary>
    /// EnhancedSecurity exposes a public API for use in working with 
    /// Stateful Forms Authentication in the .NET framework.  It also exposes the 
    /// configured configuration parameters as public static properties.
    /// </summary>
    public sealed class EnhancedSecurity
    {
        #region Fields
        ///<summary>
        /// The expected string length of a hash.
        ///</summary>
        public static readonly int HashAlgorithmStringLength = 128;
               
        ///<summary>
        /// The expected number of bytes of a hash
        ///</summary>
        public static readonly int HashAlgorithmByteLength = 64;
        
        ///<summary>
        /// The expected string length of a GUID.
        ///</summary>
        public static readonly int GuidStringLength = 36;
        
        // Thread-safe initialization
        private static readonly object LockObject;
        private static bool _initialized;

        // System.Web/Authentication and System.Web/Authentication/Forms static classes
        internal static AuthenticationSection AuthenticationConfig;
        internal static SecurityProfilerConfiguration SecurityProfilerConfig;
        internal static StatefulFormsAuthenticationConfiguration StatefulFormsAuthenticationConfig;
        
        private static SHA512Managed _hashAlgorithm;

        private static TimeSpan _formsTimeout;

        // Ticket manager fields
        private static string _ticketStoreProvider;
        private static IUserAuthenticationTicketStore _userAuthenticationTicketStore;

        private static bool _enforceClientHostAddressValidation;
        private static bool _maintainServerTicketStore;
        private static int _minimumDelayOnSuspiciousRequest;
        private static int _maximumDelayOnSuspiciousRequest;
        private static int _minimumDelayOnMaliciousRequest;
        private static int _maximumDelayOnMaliciousRequest;
        private static int _minimumDelayOnCryptographicException;
        private static int _maximumDelayOnCryptographicException;
        private static string _hashSalt;
        #endregion

        #region Methods
        /// <summary>
        /// Static constructor
        /// </summary>
        static EnhancedSecurity()
        {
            LockObject = new object();
        }

        /// <summary>
        /// Initializes configuration-related properties and validates configuration.
        /// </summary>        
        public static void Initialize()
        {
            if (!_initialized)
            {
                lock (LockObject)
                {
                    if (!_initialized)
                    {
                        FormsAuthentication.Initialize();
                        AuthenticationConfig = (AuthenticationSection)WebConfigurationManager.GetSection("system.web/authentication");
                        SecurityProfilerConfig = SecurityProfilerConfiguration.GetConfig();
                        StatefulFormsAuthenticationConfig = StatefulFormsAuthenticationConfiguration.GetConfig();

                        _hashAlgorithm = new SHA512Managed();

                        if (AuthenticationConfig == null)
                        {
                            throw new ConfigurationErrorsException("The EnhancedSecurityModule requires Forms authentication to be enabled in web.config.");
                        }

                        if (AuthenticationConfig.Mode != AuthenticationMode.Forms)
                        {
                            throw new ConfigurationErrorsException("The EnhancedSecurityModule requires Forms authentication to be enabled in web.config.");
                        }

                        if (FormsAuthentication.CookieMode != HttpCookieMode.UseCookies)
                        {
                            throw new ConfigurationErrorsException("The EnhancedSecurityModule requires Forms Authentication to use cookies (cookieless='UseCookies').");
                        }

                        /* TODO: Implement pluggable UserAuthenticationTicketStore */
                        _ticketStoreProvider = "CacheUserAuthenticationTicketProvider";
                        _userAuthenticationTicketStore = new CacheUserAuthenticationTicketProvider();

                        /* TODO: Implement/fix sliding UserAuthenticationTicketStore expiration */
                        _formsTimeout = AuthenticationConfig.Forms.Timeout;

                        _enforceClientHostAddressValidation = StatefulFormsAuthenticationConfig.EnforceClientHostAddressValidation;
                        // _maintainServerTicketStore = StatefulFormsAuthenticationConfig.StateProvider

                        _minimumDelayOnSuspiciousRequest = SecurityProfilerConfig.MinimumDelayOnSuspiciousRequest;
                        _maximumDelayOnSuspiciousRequest = SecurityProfilerConfig.MaximumDelayOnSuspiciousRequest;
                        _minimumDelayOnMaliciousRequest = SecurityProfilerConfig.MinimumDelayOnMaliciousRequest;
                        _maximumDelayOnMaliciousRequest = SecurityProfilerConfig.MaximumDelayOnMaliciousRequest;
                        _minimumDelayOnCryptographicException = SecurityProfilerConfig.MinimumDelayOnCryptographicException;
                        _maximumDelayOnCryptographicException = SecurityProfilerConfig.MaximumDelayOnCryptographicException;
                        
                        _hashSalt = StatefulFormsAuthenticationConfig.HashSalt;

                        _initialized = true;
                    }
                }

                if (UserAuthenticationTicketStore != null) UserAuthenticationTicketStore.Initialize();
            }
        }

        ///<summary>
        /// Delay the execution of the suspicious request by a random amount of time between 
        /// MinimumDelayOnSuspiciousRequest and MaximumDelayOnSuspiciousRequest
        ///</summary>
        public static void DelaySuspiciousResponse()
        {
            Thread.Sleep(new Random().Next(MinimumDelayOnSuspiciousRequest, MaximumDelayOnSuspiciousRequest));
        }

        ///<summary>
        /// Delay the execution of the malicious request by a random amount of time between 
        /// MinimumDelayOnMaliciousRequest and MaximumDelayOnMaliciousRequest
        ///</summary>
        public static void DelayMaliciousResponse()
        {
            Thread.Sleep(new Random().Next(MinimumDelayOnMaliciousRequest, MaximumDelayOnMaliciousRequest));
        }

        ///<summary>
        /// Delay the execution of a request that caused a CryptographicException by a 
        /// random amount of time between MinimumDelayOnCryptographicException and 
        /// MaximumDelayOnCryptographicException
        ///</summary>
        public static void DelayCryptographicExceptionResponse()
        {
            Thread.Sleep(new Random().Next(MinimumDelayOnCryptographicException, MaximumDelayOnCryptographicException));                
        }

        /// <summary>
        /// Calculates the hash of the FormsAuthenticationTicket's properties 
        /// concatenated together with the salt.  This is used as a first line of 
        /// defense against ticket tampering to potentially avoid an unnecessary read
        /// from the UserAuthenticationTicketStore.
        /// </summary>
        /// <param name="formsAuthenticationTicket">the formsAuthenticationTicket to 
        /// compute the hash of</param>
        /// <returns>the hash of ticket's properties</returns>
        public static string CalculateFormsAuthTicketHash(FormsAuthenticationTicket formsAuthenticationTicket)
        {
            if (formsAuthenticationTicket == null)
            {
                throw new ArgumentNullException("formsAuthenticationTicket", "The formsAuthenticationTicket parameter is required.");
            }

            Initialize();

            string input = string.Format(
                "||{0}|{1}|{2}|{3}|{4}|{5}|{6}||",
                formsAuthenticationTicket.CookiePath,
                formsAuthenticationTicket.Expiration,
                formsAuthenticationTicket.IsPersistent,
                formsAuthenticationTicket.IssueDate,
                formsAuthenticationTicket.Name,
                formsAuthenticationTicket.Version,
                HashSalt
            );

            byte[] inputBytes = Encoding.UTF32.GetBytes(input);
            byte[] hashBytes = HashAlgorithm.ComputeHash(inputBytes);

            StringBuilder sb = new StringBuilder();
            if (hashBytes.Length != HashAlgorithmByteLength)
            {
                throw new InvalidOperationException("Unable to compute hash of formsAuthenticationTicket.");
            }

            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2"));
            }

            if (sb.Length != HashAlgorithmStringLength)
            {
                throw new InvalidOperationException("Unable to compute hash of formsAuthenticationTicket");
            }

            string hash = sb.ToString();
            return hash;
        }

        /// <summary>
        /// Calculates the hash of the formsAuthenticationTicket and compares it 
        /// to the expected hash
        /// </summary>
        /// <param name="formsAuthenticationTicket">The formsAuthenticationTicket to hash</param>
        /// <param name="expectedHash">The expected hash value</param>
        /// <returns>A boolean indicating whether the expectedHash is correct</returns>
        public static bool ValidateFormsAuthTicketHash(FormsAuthenticationTicket formsAuthenticationTicket, string expectedHash)
        {
            if (formsAuthenticationTicket == null)
            {
                throw new ArgumentNullException("formsAuthenticationTicket", "formsAuthenticationTicket parameter cannot be null.");
            }

            if (expectedHash == null)
            {
                throw new ArgumentNullException("expectedHash", "expectedHash parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(expectedHash))
            {
                throw new ArgumentException("expectedHash parameter cannot be null or empty.", "expectedHash");
            }

            string calculatedHash = CalculateFormsAuthTicketHash(formsAuthenticationTicket);
            return (string.Compare(expectedHash, calculatedHash, StringComparison.Ordinal) == 0);
        }

        /// <summary>
        /// Sends a blank and expired FormsAuthentication cookie to the 
        /// client response.  This effectively removes the FormsAuthentication
        /// cookie and revokes the FormsAuthenticationTicket.  It also removes
        /// the cookie from the current Request object, preventing subsequent 
        /// code from being able to access it during the execution of the 
        /// current request.  And just for good measure, it also replaces any
        /// existing principal in the current request pipeline with an anonymous 
        /// one.
        /// </summary>
        public static void ClearAuthCookie()
        {
            Initialize();
            HttpContext current = HttpContext.Current;

            // Don't let anything see the incoming cookie 
            current.Request.Cookies.Remove(FormsAuthentication.FormsCookieName);

            GenericPrincipal anon = new GenericPrincipal(new GenericIdentity(string.Empty), null);
            Thread.CurrentPrincipal = anon;
            current.User = anon;

            // Remove the cookie from the response collection (by adding an expired/empty version).
            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName)
            {
                Expires = DateTime.Now.AddMonths(-1),
                Domain = FormsAuthentication.CookieDomain,
                Path = FormsAuthentication.FormsCookiePath
            };

            current.Response.Cookies.Add(cookie);
        }

        /// <summary>
        /// Encrypts a FormsAuthenticationTicket in an HttpCookie (using GetAuthCookie) 
        /// and includes it in the current Request's Cookies collection and/or the 
        /// Response's outbound Cookies collection.
        /// </summary>
        /// <param name="clientTicket">The FormsAuthenticationTicket to encode</param>
        /// <param name="overwriteRequestCookie">Whether or not to replace the cookie in
        /// the current Request's Cookies collection.  This will trick later executing 
        /// code on the current HTTP request into processing the updated cookie</param>
        /// <param name="writeResponseCookie">Whether or not to write the cookie to the 
        /// browser via the Response's Cookies collection.</param>
        public static void SetAuthCookie(FormsAuthenticationTicket clientTicket, bool overwriteRequestCookie, bool writeResponseCookie)
        {
            Initialize();
            HttpContext current = HttpContext.Current;

            if (overwriteRequestCookie)
            {
                current.Request.Cookies.Remove(FormsAuthentication.FormsCookieName);
                current.Request.Cookies.Add(GetAuthCookie(clientTicket));                
            }

            if (writeResponseCookie)
            {
                if (!current.Request.IsSecureConnection && FormsAuthentication.RequireSSL)
                {
                    throw new HttpException("Connection not secure while creating secure cookie");
                }
                current.Response.Cookies.Add(GetAuthCookie(clientTicket));
            }
        }

        /// <summary>
        /// Creates an HttpCookie containing an encrypted FormsAuthenticationTicket.
        /// The ticket must contain an hash and key into the UserAuthenticationTicketStore.
        /// </summary>
        /// <param name="ticket">The FormsAuthenticationTicket to encode</param>
        /// <returns>An HttpCookie containing the encrypted FormsAuthenticationTicket</returns>
        public static HttpCookie GetAuthCookie(FormsAuthenticationTicket ticket)
        {
            Initialize();

            /*
            if (string.IsNullOrEmpty(ticket.UserData))
            {
                throw new InvalidOperationException("The ticket's UserData property is not set properly.");
            }
            */

            string str = FormsAuthentication.Encrypt(ticket);

            if (String.IsNullOrEmpty(str))
            {
                throw new HttpException("Unable to encrypt cookie ticket");
            }

            HttpCookie cookie = new HttpCookie(FormsAuthentication.FormsCookieName, str)
            {
                HttpOnly = true,
                Path = FormsAuthentication.FormsCookiePath,
                Secure = FormsAuthentication.RequireSSL
            };

            // Per http://support.microsoft.com/kb/900111 :
            // In ASP.NET 2.0, forms authentication cookies are HttpOnly cookies. 
            // HttpOnly cookies cannot be accessed through client script. This 
            // functionality helps reduce the chances of replay attacks.

            if (FormsAuthentication.CookieDomain != null)
            {
                cookie.Domain = FormsAuthentication.CookieDomain;
            }

            if (ticket.IsPersistent)
            {
                cookie.Expires = ticket.Expiration;
            }

            return cookie;
        }

        /// <summary>
        /// Creates a FormsAuthenticationTicket for storage on the client.
        /// The UserData field contains the server key, which can be 
        /// used by the server-side UserAuthenticationTicketStore to retrieve validation data 
        /// and additional details about the ticket (e.g. IP address)
        /// </summary>
        /// <param name="username">User associated with the ticket</param>
        /// <param name="cookiePath">Relative path on server in which cookie is valid</param>
        /// <param name="serverKey">UserAuthenticationTicketStore key</param>
        /// <param name="validFromDate">Ticket valid from date</param>
        /// <param name="validUntilDate">Ticket valid to date</param>
        /// <param name="persistent">Ticket can persist across browser sessions</param>
        /// <returns>Instance of a FormsAuthenticationTicket</returns>
        public static FormsAuthenticationTicket CreateFormsAuthTicket(string username, string cookiePath, string serverKey, DateTime? validFromDate, DateTime? validUntilDate, bool persistent)
        {
            if (username == null)
            {
                throw new ArgumentNullException("username", "username parameter cannot be null or empty.");
            }
            if (string.IsNullOrEmpty(username))
            {
                throw new ArgumentException("username parameter cannot be null or empty.", "username");
            }

            /*
            if (serverKey == null)
            {
                throw new ArgumentNullException("serverKey", "serverKey parameter cannot be null or empty.");
            }
            else if (string.IsNullOrEmpty(serverKey))
            {
                throw new ArgumentException("serverKey parameter cannot be null or empty.", "serverKey");
            }                
            */

            Initialize();

            DateTime fromDate = validFromDate.HasValue ? validFromDate.Value : DateTime.Now;
            DateTime toDate = validUntilDate.HasValue ? validUntilDate.Value : fromDate.Add(FormsTimeout);

            FormsAuthenticationTicket ticket = new FormsAuthenticationTicket(
                2,
                username,
                fromDate,
                toDate,
                persistent,
                serverKey ?? string.Empty,
                cookiePath ?? FormsAuthentication.FormsCookiePath
            );

            return ticket;
        }
        #endregion

        #region Internal Methods
        internal static FormsAuthenticationStatus GetFormsAuthStatus()
        {
            if (HttpContext.Current.Items["TicketStatus"] != null && !string.IsNullOrEmpty(HttpContext.Current.Items["TicketStatus"].ToString()))
            {
                try
                {
                    return (FormsAuthenticationStatus)Enum.Parse(typeof(FormsAuthenticationStatus), HttpContext.Current.Items["TicketStatus"].ToString());
                }
                catch
                {
                    return FormsAuthenticationStatus.Invalid;
                }
            }
            return FormsAuthenticationStatus.NotFound;
        }

        internal static void SetFormsAuthStatus(FormsAuthenticationStatus status)
        {
            switch (status)
            {
                case FormsAuthenticationStatus.Valid:
                case FormsAuthenticationStatus.NotFound:
                    HttpContext.Current.Items["TicketStatus"] = status.ToString();
                    break;
                default:
                    HttpContext.Current.Items["TicketStatus"] = FormsAuthenticationStatus.Invalid.ToString();
                    ClearAuthCookie();
                    break;
            }
        }
        #endregion

        #region Properties
        /// <summary>
        /// The ticket store containing a record of tickets issued by the 
        /// server. 
        /// <remarks>
        /// Currently supported values: CacheUserAuthenticationTicketProvider
        /// </remarks>
        /// </summary>
        public static string TicketStoreProvider
        {
            get
            {
                Initialize();
                return _ticketStoreProvider;
            }
        }

        /// <summary>
        /// An instance of the provider specified in the TicketStoreProvider property.
        /// The UserAuthenticationTicketStore allows access to validation-related information about outstanding 
        /// FormsAuthenticationCookies and FormsAuthenticationTickets along with the host 
        /// address of the client that initially requested the ticket.
        /// </summary>
        public static IUserAuthenticationTicketStore UserAuthenticationTicketStore
        {
            get
            {
                Initialize();
                return _userAuthenticationTicketStore;
            }
        }

        /// <summary>
        /// An instance of a Hash algorithm that is used to calculate the checksum of a 
        /// FormsAuthenticationTicket's properties.
        /// </summary>
        public static SHA512Managed HashAlgorithm
        {
            get
            {
                Initialize();
                return _hashAlgorithm;
            }
        }

        /// <summary>
        /// The Forms Timeout property set in system.web/authentication/forms
        /// </summary>
        public static TimeSpan FormsTimeout
        {
            get
            {
                Initialize();
                return _formsTimeout;
            }
        }

        /// <summary>
        /// Whether or not to enforce client host address validation.  With this option enabled, a FormsAuthenticationTicket
        /// will only validate received from the IP address on which it was generated.  This prevents ticket stealing, but
        /// will result in a user being logged out in the event that their IP address changes.
        /// </summary>
        public static bool EnforceClientHostAddressValidation
        {
            get
            {
                Initialize();
                return _enforceClientHostAddressValidation;
            }
        }

        /// <summary>
        /// Indicates whether or not to maintain a UserAuthenticationTicketStore on the server.  With this disabled,
        /// the ticket validation process is still strenghtened on account of the hash generation
        /// and validation and request processing performance increases.  
        /// 
        /// However, Security features which depend on a stateful ticket store (such as enhanced 
        /// ticket validation, kicking, banning) will not be available.
        /// </summary>
        public static bool MaintainServerTicketStore
        {
            get
            {
                Initialize();
                return _maintainServerTicketStore;
            }
        }

        /// <summary>
        /// The minimum number of milliseconds to delay on receipt of a suspicious request
        /// </summary>
        public static int MinimumDelayOnSuspiciousRequest
        {
            get
            {
                Initialize();
                return _minimumDelayOnSuspiciousRequest;
            }
        }

        /// <summary>
        /// The maximum number of milliseconds to delay on receipt of a suspicious request
        /// </summary>
        public static int MaximumDelayOnSuspiciousRequest
        {
            get
            {
                Initialize();
                return _maximumDelayOnSuspiciousRequest;
            }
        }

        /// <summary>
        /// The minimum number of milliseconds to delay on receipt of a malicious request
        /// </summary>
        public static int MinimumDelayOnMaliciousRequest
        {
            get
            {
                Initialize();
                return _minimumDelayOnMaliciousRequest;
            }
        }

        /// <summary>
        /// The maximum number of milliseconds to delay on receipt of a malicious request
        /// </summary>
        public static int MaximumDelayOnMaliciousRequest
        {
            get
            {
                Initialize();
                return _maximumDelayOnMaliciousRequest;
            }
        }

        /// <summary>
        /// The minimum number of milliseconds to delay on production of a CryptographicException
        /// </summary>
        public static int MinimumDelayOnCryptographicException
        {
            get
            {
                Initialize();
                return _minimumDelayOnCryptographicException;
            }
        }

        /// <summary>
        /// The maximum number of milliseconds to delay on production of a CryptographicException
        /// </summary>
        public static int MaximumDelayOnCryptographicException
        {
            get
            {
                Initialize();
                return _maximumDelayOnCryptographicException;
            }
        }

        /// <summary>
        /// The string to salt generated hashes with to prevent tampering.  Always set a unique hash salt and
        /// keep it safe
        /// </summary>
        public static string HashSalt
        {
            get
            {
                Initialize();
                return _hashSalt;
            }
        }
        #endregion
    }
}